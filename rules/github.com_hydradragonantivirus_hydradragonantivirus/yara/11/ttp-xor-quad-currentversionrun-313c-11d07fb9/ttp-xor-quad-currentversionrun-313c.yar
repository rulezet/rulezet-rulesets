rule TTP_XOR_QUAD_CurrentVersionRun_313c {
  strings:
    $key_313c = { 62 53 [2] 46 5d [2] 6d 71 [2] 43 53 [2] 57 48 [2] 58 52 [2] 46 4f [2] 44 4e [2] 5f 48 [2] 43 4f [2] 5f 60 }

  condition:
    any of them
}
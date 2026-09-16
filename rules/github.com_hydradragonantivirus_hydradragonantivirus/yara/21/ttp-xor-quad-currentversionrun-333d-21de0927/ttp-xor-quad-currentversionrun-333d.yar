rule TTP_XOR_QUAD_CurrentVersionRun_333d {
  strings:
    $key_333d = { 60 52 [2] 44 5c [2] 6f 70 [2] 41 52 [2] 55 49 [2] 5a 53 [2] 44 4e [2] 46 4f [2] 5d 49 [2] 41 4e [2] 5d 61 }

  condition:
    any of them
}
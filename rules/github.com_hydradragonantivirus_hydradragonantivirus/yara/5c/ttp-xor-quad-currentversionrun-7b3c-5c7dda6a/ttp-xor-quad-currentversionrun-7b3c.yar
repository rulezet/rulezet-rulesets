rule TTP_XOR_QUAD_CurrentVersionRun_7b3c {
  strings:
    $key_7b3c = { 28 53 [2] 0c 5d [2] 27 71 [2] 09 53 [2] 1d 48 [2] 12 52 [2] 0c 4f [2] 0e 4e [2] 15 48 [2] 09 4f [2] 15 60 }

  condition:
    any of them
}
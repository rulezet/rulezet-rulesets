rule TTP_XOR_QUAD_CurrentVersionRun_640a {
  strings:
    $key_640a = { 37 65 [2] 13 6b [2] 38 47 [2] 16 65 [2] 02 7e [2] 0d 64 [2] 13 79 [2] 11 78 [2] 0a 7e [2] 16 79 [2] 0a 56 }

  condition:
    any of them
}
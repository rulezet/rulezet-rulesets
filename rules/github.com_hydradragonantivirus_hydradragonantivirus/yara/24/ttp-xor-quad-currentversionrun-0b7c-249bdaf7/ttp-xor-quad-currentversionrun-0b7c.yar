rule TTP_XOR_QUAD_CurrentVersionRun_0b7c {
  strings:
    $key_0b7c = { 58 13 [2] 7c 1d [2] 57 31 [2] 79 13 [2] 6d 08 [2] 62 12 [2] 7c 0f [2] 7e 0e [2] 65 08 [2] 79 0f [2] 65 20 }

  condition:
    any of them
}
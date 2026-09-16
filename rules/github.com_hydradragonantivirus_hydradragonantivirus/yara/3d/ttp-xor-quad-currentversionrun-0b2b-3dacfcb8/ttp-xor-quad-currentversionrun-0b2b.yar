rule TTP_XOR_QUAD_CurrentVersionRun_0b2b {
  strings:
    $key_0b2b = { 58 44 [2] 7c 4a [2] 57 66 [2] 79 44 [2] 6d 5f [2] 62 45 [2] 7c 58 [2] 7e 59 [2] 65 5f [2] 79 58 [2] 65 77 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0b76 {
  strings:
    $key_0b76 = { 58 19 [2] 7c 17 [2] 57 3b [2] 79 19 [2] 6d 02 [2] 62 18 [2] 7c 05 [2] 7e 04 [2] 65 02 [2] 79 05 [2] 65 2a }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_6904 {
  strings:
    $key_6904 = { 3a 6b [2] 1e 65 [2] 35 49 [2] 1b 6b [2] 0f 70 [2] 00 6a [2] 1e 77 [2] 1c 76 [2] 07 70 [2] 1b 77 [2] 07 58 }

  condition:
    any of them
}
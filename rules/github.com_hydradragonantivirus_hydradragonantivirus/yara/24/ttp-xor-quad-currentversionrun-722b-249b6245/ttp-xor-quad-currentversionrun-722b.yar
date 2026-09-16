rule TTP_XOR_QUAD_CurrentVersionRun_722b {
  strings:
    $key_722b = { 21 44 [2] 05 4a [2] 2e 66 [2] 00 44 [2] 14 5f [2] 1b 45 [2] 05 58 [2] 07 59 [2] 1c 5f [2] 00 58 [2] 1c 77 }

  condition:
    any of them
}
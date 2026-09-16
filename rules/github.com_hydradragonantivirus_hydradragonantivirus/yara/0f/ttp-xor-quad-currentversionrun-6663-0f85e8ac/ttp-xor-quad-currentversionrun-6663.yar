rule TTP_XOR_QUAD_CurrentVersionRun_6663 {
  strings:
    $key_6663 = { 35 0c [2] 11 02 [2] 3a 2e [2] 14 0c [2] 00 17 [2] 0f 0d [2] 11 10 [2] 13 11 [2] 08 17 [2] 14 10 [2] 08 3f }

  condition:
    any of them
}
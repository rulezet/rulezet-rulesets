rule TTP_XOR_QUAD_CurrentVersionRun_6602 {
  strings:
    $key_6602 = { 35 6d [2] 11 63 [2] 3a 4f [2] 14 6d [2] 00 76 [2] 0f 6c [2] 11 71 [2] 13 70 [2] 08 76 [2] 14 71 [2] 08 5e }

  condition:
    any of them
}
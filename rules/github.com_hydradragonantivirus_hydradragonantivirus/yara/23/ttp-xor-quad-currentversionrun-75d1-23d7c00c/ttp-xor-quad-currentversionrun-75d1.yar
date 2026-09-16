rule TTP_XOR_QUAD_CurrentVersionRun_75d1 {
  strings:
    $key_75d1 = { 26 be [2] 02 b0 [2] 29 9c [2] 07 be [2] 13 a5 [2] 1c bf [2] 02 a2 [2] 00 a3 [2] 1b a5 [2] 07 a2 [2] 1b 8d }

  condition:
    any of them
}
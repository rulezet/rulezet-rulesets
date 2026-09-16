rule TTP_XOR_QUAD_CurrentVersionRun_04b3 {
  strings:
    $key_04b3 = { 57 dc [2] 73 d2 [2] 58 fe [2] 76 dc [2] 62 c7 [2] 6d dd [2] 73 c0 [2] 71 c1 [2] 6a c7 [2] 76 c0 [2] 6a ef }

  condition:
    any of them
}
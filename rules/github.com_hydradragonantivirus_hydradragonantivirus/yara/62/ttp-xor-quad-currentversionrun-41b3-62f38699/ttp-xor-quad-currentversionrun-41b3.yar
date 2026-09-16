rule TTP_XOR_QUAD_CurrentVersionRun_41b3 {
  strings:
    $key_41b3 = { 12 dc [2] 36 d2 [2] 1d fe [2] 33 dc [2] 27 c7 [2] 28 dd [2] 36 c0 [2] 34 c1 [2] 2f c7 [2] 33 c0 [2] 2f ef }

  condition:
    any of them
}
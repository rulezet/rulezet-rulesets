rule TTP_XOR_QUAD_CurrentVersionRun_21b3 {
  strings:
    $key_21b3 = { 72 dc [2] 56 d2 [2] 7d fe [2] 53 dc [2] 47 c7 [2] 48 dd [2] 56 c0 [2] 54 c1 [2] 4f c7 [2] 53 c0 [2] 4f ef }

  condition:
    any of them
}
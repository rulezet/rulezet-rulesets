rule TTP_XOR_QUAD_CurrentVersionRun_14b3 {
  strings:
    $key_14b3 = { 47 dc [2] 63 d2 [2] 48 fe [2] 66 dc [2] 72 c7 [2] 7d dd [2] 63 c0 [2] 61 c1 [2] 7a c7 [2] 66 c0 [2] 7a ef }

  condition:
    any of them
}
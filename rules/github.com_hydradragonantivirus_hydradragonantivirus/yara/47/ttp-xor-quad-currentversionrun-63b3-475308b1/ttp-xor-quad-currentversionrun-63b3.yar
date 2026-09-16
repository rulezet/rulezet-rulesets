rule TTP_XOR_QUAD_CurrentVersionRun_63b3 {
  strings:
    $key_63b3 = { 30 dc [2] 14 d2 [2] 3f fe [2] 11 dc [2] 05 c7 [2] 0a dd [2] 14 c0 [2] 16 c1 [2] 0d c7 [2] 11 c0 [2] 0d ef }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_43b3 {
  strings:
    $key_43b3 = { 10 dc [2] 34 d2 [2] 1f fe [2] 31 dc [2] 25 c7 [2] 2a dd [2] 34 c0 [2] 36 c1 [2] 2d c7 [2] 31 c0 [2] 2d ef }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_13b3 {
  strings:
    $key_13b3 = { 40 dc [2] 64 d2 [2] 4f fe [2] 61 dc [2] 75 c7 [2] 7a dd [2] 64 c0 [2] 66 c1 [2] 7d c7 [2] 61 c0 [2] 7d ef }

  condition:
    any of them
}
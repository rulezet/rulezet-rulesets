rule TTP_XOR_QUAD_CurrentVersionRun_e3b3 {
  strings:
    $key_e3b3 = { b0 dc [2] 94 d2 [2] bf fe [2] 91 dc [2] 85 c7 [2] 8a dd [2] 94 c0 [2] 96 c1 [2] 8d c7 [2] 91 c0 [2] 8d ef }

  condition:
    any of them
}
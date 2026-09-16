rule TTP_XOR_QUAD_CurrentVersionRun_d4b3 {
  strings:
    $key_d4b3 = { 87 dc [2] a3 d2 [2] 88 fe [2] a6 dc [2] b2 c7 [2] bd dd [2] a3 c0 [2] a1 c1 [2] ba c7 [2] a6 c0 [2] ba ef }

  condition:
    any of them
}
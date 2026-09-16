rule TTP_XOR_QUAD_CurrentVersionRun_f1b2 {
  strings:
    $key_f1b2 = { a2 dd [2] 86 d3 [2] ad ff [2] 83 dd [2] 97 c6 [2] 98 dc [2] 86 c1 [2] 84 c0 [2] 9f c6 [2] 83 c1 [2] 9f ee }

  condition:
    any of them
}
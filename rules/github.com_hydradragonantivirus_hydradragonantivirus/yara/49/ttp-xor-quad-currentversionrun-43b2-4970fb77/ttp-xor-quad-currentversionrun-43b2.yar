rule TTP_XOR_QUAD_CurrentVersionRun_43b2 {
  strings:
    $key_43b2 = { 10 dd [2] 34 d3 [2] 1f ff [2] 31 dd [2] 25 c6 [2] 2a dc [2] 34 c1 [2] 36 c0 [2] 2d c6 [2] 31 c1 [2] 2d ee }

  condition:
    any of them
}
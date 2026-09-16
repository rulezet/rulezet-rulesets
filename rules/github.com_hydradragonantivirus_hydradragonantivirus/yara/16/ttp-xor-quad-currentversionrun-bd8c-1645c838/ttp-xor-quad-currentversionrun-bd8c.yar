rule TTP_XOR_QUAD_CurrentVersionRun_bd8c {
  strings:
    $key_bd8c = { ee e3 [2] ca ed [2] e1 c1 [2] cf e3 [2] db f8 [2] d4 e2 [2] ca ff [2] c8 fe [2] d3 f8 [2] cf ff [2] d3 d0 }

  condition:
    any of them
}
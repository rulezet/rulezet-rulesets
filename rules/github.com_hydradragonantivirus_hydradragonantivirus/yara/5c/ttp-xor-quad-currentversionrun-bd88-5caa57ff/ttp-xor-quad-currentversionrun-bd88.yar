rule TTP_XOR_QUAD_CurrentVersionRun_bd88 {
  strings:
    $key_bd88 = { ee e7 [2] ca e9 [2] e1 c5 [2] cf e7 [2] db fc [2] d4 e6 [2] ca fb [2] c8 fa [2] d3 fc [2] cf fb [2] d3 d4 }

  condition:
    any of them
}
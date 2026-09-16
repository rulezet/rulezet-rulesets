rule TTP_XOR_QUAD_CurrentVersionRun_b588 {
  strings:
    $key_b588 = { e6 e7 [2] c2 e9 [2] e9 c5 [2] c7 e7 [2] d3 fc [2] dc e6 [2] c2 fb [2] c0 fa [2] db fc [2] c7 fb [2] db d4 }

  condition:
    any of them
}
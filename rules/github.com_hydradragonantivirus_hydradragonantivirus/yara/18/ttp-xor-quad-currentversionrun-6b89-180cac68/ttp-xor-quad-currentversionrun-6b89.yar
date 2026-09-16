rule TTP_XOR_QUAD_CurrentVersionRun_6b89 {
  strings:
    $key_6b89 = { 38 e6 [2] 1c e8 [2] 37 c4 [2] 19 e6 [2] 0d fd [2] 02 e7 [2] 1c fa [2] 1e fb [2] 05 fd [2] 19 fa [2] 05 d5 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0589 {
  strings:
    $key_0589 = { 56 e6 [2] 72 e8 [2] 59 c4 [2] 77 e6 [2] 63 fd [2] 6c e7 [2] 72 fa [2] 70 fb [2] 6b fd [2] 77 fa [2] 6b d5 }

  condition:
    any of them
}
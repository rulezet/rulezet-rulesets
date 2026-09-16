rule TTP_XOR_QUAD_CurrentVersionRun_48b6 {
  strings:
    $key_48b6 = { 1b d9 [2] 3f d7 [2] 14 fb [2] 3a d9 [2] 2e c2 [2] 21 d8 [2] 3f c5 [2] 3d c4 [2] 26 c2 [2] 3a c5 [2] 26 ea }

  condition:
    any of them
}
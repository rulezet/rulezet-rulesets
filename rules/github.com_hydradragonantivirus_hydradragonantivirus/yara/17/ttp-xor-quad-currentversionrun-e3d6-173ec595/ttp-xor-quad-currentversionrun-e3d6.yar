rule TTP_XOR_QUAD_CurrentVersionRun_e3d6 {
  strings:
    $key_e3d6 = { b0 b9 [2] 94 b7 [2] bf 9b [2] 91 b9 [2] 85 a2 [2] 8a b8 [2] 94 a5 [2] 96 a4 [2] 8d a2 [2] 91 a5 [2] 8d 8a }

  condition:
    any of them
}
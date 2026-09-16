rule TTP_XOR_QUAD_CurrentVersionRun_e3d7 {
  strings:
    $key_e3d7 = { b0 b8 [2] 94 b6 [2] bf 9a [2] 91 b8 [2] 85 a3 [2] 8a b9 [2] 94 a4 [2] 96 a5 [2] 8d a3 [2] 91 a4 [2] 8d 8b }

  condition:
    any of them
}
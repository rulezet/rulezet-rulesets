rule TTP_XOR_QUAD_CurrentVersionRun_f3d7 {
  strings:
    $key_f3d7 = { a0 b8 [2] 84 b6 [2] af 9a [2] 81 b8 [2] 95 a3 [2] 9a b9 [2] 84 a4 [2] 86 a5 [2] 9d a3 [2] 81 a4 [2] 9d 8b }

  condition:
    any of them
}
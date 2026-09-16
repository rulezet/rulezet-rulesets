rule TTP_XOR_QUAD_CurrentVersionRun_f3d6 {
  strings:
    $key_f3d6 = { a0 b9 [2] 84 b7 [2] af 9b [2] 81 b9 [2] 95 a2 [2] 9a b8 [2] 84 a5 [2] 86 a4 [2] 9d a2 [2] 81 a5 [2] 9d 8a }

  condition:
    any of them
}
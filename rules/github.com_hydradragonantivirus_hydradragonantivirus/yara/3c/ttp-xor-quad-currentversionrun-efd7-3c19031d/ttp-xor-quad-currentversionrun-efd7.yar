rule TTP_XOR_QUAD_CurrentVersionRun_efd7 {
  strings:
    $key_efd7 = { bc b8 [2] 98 b6 [2] b3 9a [2] 9d b8 [2] 89 a3 [2] 86 b9 [2] 98 a4 [2] 9a a5 [2] 81 a3 [2] 9d a4 [2] 81 8b }

  condition:
    any of them
}
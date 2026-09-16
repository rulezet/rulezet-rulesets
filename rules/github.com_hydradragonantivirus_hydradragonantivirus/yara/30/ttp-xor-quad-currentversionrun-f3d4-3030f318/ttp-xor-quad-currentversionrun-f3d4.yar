rule TTP_XOR_QUAD_CurrentVersionRun_f3d4 {
  strings:
    $key_f3d4 = { a0 bb [2] 84 b5 [2] af 99 [2] 81 bb [2] 95 a0 [2] 9a ba [2] 84 a7 [2] 86 a6 [2] 9d a0 [2] 81 a7 [2] 9d 88 }

  condition:
    any of them
}
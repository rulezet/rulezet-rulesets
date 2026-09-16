rule TTP_XOR_QUAD_CurrentVersionRun_61c9 {
  strings:
    $key_61c9 = { 32 a6 [2] 16 a8 [2] 3d 84 [2] 13 a6 [2] 07 bd [2] 08 a7 [2] 16 ba [2] 14 bb [2] 0f bd [2] 13 ba [2] 0f 95 }

  condition:
    any of them
}
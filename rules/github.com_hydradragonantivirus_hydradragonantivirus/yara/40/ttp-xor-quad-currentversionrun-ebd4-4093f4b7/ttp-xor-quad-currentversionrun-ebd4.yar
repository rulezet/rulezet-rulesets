rule TTP_XOR_QUAD_CurrentVersionRun_ebd4 {
  strings:
    $key_ebd4 = { b8 bb [2] 9c b5 [2] b7 99 [2] 99 bb [2] 8d a0 [2] 82 ba [2] 9c a7 [2] 9e a6 [2] 85 a0 [2] 99 a7 [2] 85 88 }

  condition:
    any of them
}
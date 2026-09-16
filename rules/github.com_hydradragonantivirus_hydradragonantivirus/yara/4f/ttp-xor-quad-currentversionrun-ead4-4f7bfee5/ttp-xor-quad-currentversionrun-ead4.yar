rule TTP_XOR_QUAD_CurrentVersionRun_ead4 {
  strings:
    $key_ead4 = { b9 bb [2] 9d b5 [2] b6 99 [2] 98 bb [2] 8c a0 [2] 83 ba [2] 9d a7 [2] 9f a6 [2] 84 a0 [2] 98 a7 [2] 84 88 }

  condition:
    any of them
}
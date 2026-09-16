rule TTP_XOR_QUAD_CurrentVersionRun_dda8 {
  strings:
    $key_dda8 = { 8e c7 [2] aa c9 [2] 81 e5 [2] af c7 [2] bb dc [2] b4 c6 [2] aa db [2] a8 da [2] b3 dc [2] af db [2] b3 f4 }

  condition:
    any of them
}
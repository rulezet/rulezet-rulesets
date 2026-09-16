rule TTP_XOR_QUAD_CurrentVersionRun_dda9 {
  strings:
    $key_dda9 = { 8e c6 [2] aa c8 [2] 81 e4 [2] af c6 [2] bb dd [2] b4 c7 [2] aa da [2] a8 db [2] b3 dd [2] af da [2] b3 f5 }

  condition:
    any of them
}
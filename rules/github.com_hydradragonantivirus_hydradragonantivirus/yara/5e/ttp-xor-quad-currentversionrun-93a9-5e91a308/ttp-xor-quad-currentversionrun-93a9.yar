rule TTP_XOR_QUAD_CurrentVersionRun_93a9 {
  strings:
    $key_93a9 = { c0 c6 [2] e4 c8 [2] cf e4 [2] e1 c6 [2] f5 dd [2] fa c7 [2] e4 da [2] e6 db [2] fd dd [2] e1 da [2] fd f5 }

  condition:
    any of them
}
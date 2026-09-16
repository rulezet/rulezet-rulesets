rule TTP_XOR_QUAD_CurrentVersionRun_d4a9 {
  strings:
    $key_d4a9 = { 87 c6 [2] a3 c8 [2] 88 e4 [2] a6 c6 [2] b2 dd [2] bd c7 [2] a3 da [2] a1 db [2] ba dd [2] a6 da [2] ba f5 }

  condition:
    any of them
}
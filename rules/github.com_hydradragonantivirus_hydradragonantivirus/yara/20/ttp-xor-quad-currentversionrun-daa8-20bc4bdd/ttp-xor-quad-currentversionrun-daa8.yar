rule TTP_XOR_QUAD_CurrentVersionRun_daa8 {
  strings:
    $key_daa8 = { 89 c7 [2] ad c9 [2] 86 e5 [2] a8 c7 [2] bc dc [2] b3 c6 [2] ad db [2] af da [2] b4 dc [2] a8 db [2] b4 f4 }

  condition:
    any of them
}
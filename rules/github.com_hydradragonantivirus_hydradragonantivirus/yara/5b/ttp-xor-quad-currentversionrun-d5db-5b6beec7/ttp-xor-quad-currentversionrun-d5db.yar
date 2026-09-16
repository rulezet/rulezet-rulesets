rule TTP_XOR_QUAD_CurrentVersionRun_d5db {
  strings:
    $key_d5db = { 86 b4 [2] a2 ba [2] 89 96 [2] a7 b4 [2] b3 af [2] bc b5 [2] a2 a8 [2] a0 a9 [2] bb af [2] a7 a8 [2] bb 87 }

  condition:
    any of them
}
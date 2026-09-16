rule TTP_XOR_QUAD_CurrentVersionRun_c8a9 {
  strings:
    $key_c8a9 = { 9b c6 [2] bf c8 [2] 94 e4 [2] ba c6 [2] ae dd [2] a1 c7 [2] bf da [2] bd db [2] a6 dd [2] ba da [2] a6 f5 }

  condition:
    any of them
}
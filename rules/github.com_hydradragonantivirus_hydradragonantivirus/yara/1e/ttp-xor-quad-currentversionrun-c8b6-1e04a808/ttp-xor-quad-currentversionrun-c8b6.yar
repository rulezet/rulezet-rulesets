rule TTP_XOR_QUAD_CurrentVersionRun_c8b6 {
  strings:
    $key_c8b6 = { 9b d9 [2] bf d7 [2] 94 fb [2] ba d9 [2] ae c2 [2] a1 d8 [2] bf c5 [2] bd c4 [2] a6 c2 [2] ba c5 [2] a6 ea }

  condition:
    any of them
}
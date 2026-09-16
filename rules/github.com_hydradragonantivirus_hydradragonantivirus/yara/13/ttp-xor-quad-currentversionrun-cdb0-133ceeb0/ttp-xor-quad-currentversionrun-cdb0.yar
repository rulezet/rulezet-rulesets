rule TTP_XOR_QUAD_CurrentVersionRun_cdb0 {
  strings:
    $key_cdb0 = { 9e df [2] ba d1 [2] 91 fd [2] bf df [2] ab c4 [2] a4 de [2] ba c3 [2] b8 c2 [2] a3 c4 [2] bf c3 [2] a3 ec }

  condition:
    any of them
}
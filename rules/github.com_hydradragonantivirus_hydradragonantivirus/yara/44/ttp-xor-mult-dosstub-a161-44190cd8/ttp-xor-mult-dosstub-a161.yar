rule TTP_XOR_MULT_DOSStub_a161 {
  strings:
    $key_a161 = { f5 09 [2] 81 11 [2] c6 13 [2] 81 02 [2] cf 0e [2] c3 04 [2] d4 0f [2] cf 41 [2] f2 }

  condition:
    any of them
}
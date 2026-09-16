rule TTP_XOR_MULT_DOSStub_d8b5 {
  strings:
    $key_d8b5 = { 8c dd [2] f8 c5 [2] bf c7 [2] f8 d6 [2] b6 da [2] ba d0 [2] ad db [2] b6 95 [2] 8b }

  condition:
    any of them
}
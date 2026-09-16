rule TTP_XOR_MULT_DOSStub_d8b4 {
  strings:
    $key_d8b4 = { 8c dc [2] f8 c4 [2] bf c6 [2] f8 d7 [2] b6 db [2] ba d1 [2] ad da [2] b6 94 [2] 8b }

  condition:
    any of them
}
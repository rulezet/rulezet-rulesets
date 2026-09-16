rule TTP_XOR_MULT_DOSStub_d986 {
  strings:
    $key_d986 = { 8d ee [2] f9 f6 [2] be f4 [2] f9 e5 [2] b7 e9 [2] bb e3 [2] ac e8 [2] b7 a6 [2] 8a }

  condition:
    any of them
}
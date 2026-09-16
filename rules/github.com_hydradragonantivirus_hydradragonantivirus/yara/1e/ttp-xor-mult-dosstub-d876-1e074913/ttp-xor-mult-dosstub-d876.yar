rule TTP_XOR_MULT_DOSStub_d876 {
  strings:
    $key_d876 = { 8c 1e [2] f8 06 [2] bf 04 [2] f8 15 [2] b6 19 [2] ba 13 [2] ad 18 [2] b6 56 [2] 8b }

  condition:
    any of them
}
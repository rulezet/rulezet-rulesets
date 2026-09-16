rule TTP_XOR_MULT_DOSStub_d3be {
  strings:
    $key_d3be = { 87 d6 [2] f3 ce [2] b4 cc [2] f3 dd [2] bd d1 [2] b1 db [2] a6 d0 [2] bd 9e [2] 80 }

  condition:
    any of them
}
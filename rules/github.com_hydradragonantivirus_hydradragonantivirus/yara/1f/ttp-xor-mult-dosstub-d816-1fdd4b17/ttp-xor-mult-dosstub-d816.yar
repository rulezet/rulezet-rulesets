rule TTP_XOR_MULT_DOSStub_d816 {
  strings:
    $key_d816 = { 8c 7e [2] f8 66 [2] bf 64 [2] f8 75 [2] b6 79 [2] ba 73 [2] ad 78 [2] b6 36 [2] 8b }

  condition:
    any of them
}
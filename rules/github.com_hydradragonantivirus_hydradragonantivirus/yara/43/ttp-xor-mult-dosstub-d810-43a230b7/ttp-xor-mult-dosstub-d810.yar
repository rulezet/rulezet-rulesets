rule TTP_XOR_MULT_DOSStub_d810 {
  strings:
    $key_d810 = { 8c 78 [2] f8 60 [2] bf 62 [2] f8 73 [2] b6 7f [2] ba 75 [2] ad 7e [2] b6 30 [2] 8b }

  condition:
    any of them
}
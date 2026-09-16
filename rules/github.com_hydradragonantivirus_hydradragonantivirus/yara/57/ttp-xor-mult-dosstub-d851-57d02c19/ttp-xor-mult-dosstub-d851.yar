rule TTP_XOR_MULT_DOSStub_d851 {
  strings:
    $key_d851 = { 8c 39 [2] f8 21 [2] bf 23 [2] f8 32 [2] b6 3e [2] ba 34 [2] ad 3f [2] b6 71 [2] 8b }

  condition:
    any of them
}
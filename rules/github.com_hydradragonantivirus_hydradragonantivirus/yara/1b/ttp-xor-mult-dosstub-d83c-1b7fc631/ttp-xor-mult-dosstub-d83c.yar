rule TTP_XOR_MULT_DOSStub_d83c {
  strings:
    $key_d83c = { 8c 54 [2] f8 4c [2] bf 4e [2] f8 5f [2] b6 53 [2] ba 59 [2] ad 52 [2] b6 1c [2] 8b }

  condition:
    any of them
}
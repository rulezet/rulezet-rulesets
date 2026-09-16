rule TTP_XOR_MULT_DOSStub_d84e {
  strings:
    $key_d84e = { 8c 26 [2] f8 3e [2] bf 3c [2] f8 2d [2] b6 21 [2] ba 2b [2] ad 20 [2] b6 6e [2] 8b }

  condition:
    any of them
}
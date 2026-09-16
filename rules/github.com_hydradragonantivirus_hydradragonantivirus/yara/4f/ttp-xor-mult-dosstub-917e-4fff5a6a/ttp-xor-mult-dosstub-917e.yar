rule TTP_XOR_MULT_DOSStub_917e {
  strings:
    $key_917e = { c5 16 [2] b1 0e [2] f6 0c [2] b1 1d [2] ff 11 [2] f3 1b [2] e4 10 [2] ff 5e [2] c2 }

  condition:
    any of them
}
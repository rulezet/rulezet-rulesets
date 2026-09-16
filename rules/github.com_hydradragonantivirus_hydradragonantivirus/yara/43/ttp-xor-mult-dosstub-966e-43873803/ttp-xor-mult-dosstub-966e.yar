rule TTP_XOR_MULT_DOSStub_966e {
  strings:
    $key_966e = { c2 06 [2] b6 1e [2] f1 1c [2] b6 0d [2] f8 01 [2] f4 0b [2] e3 00 [2] f8 4e [2] c5 }

  condition:
    any of them
}
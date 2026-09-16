rule TTP_XOR_MULT_DOSStub_976e {
  strings:
    $key_976e = { c3 06 [2] b7 1e [2] f0 1c [2] b7 0d [2] f9 01 [2] f5 0b [2] e2 00 [2] f9 4e [2] c4 }

  condition:
    any of them
}
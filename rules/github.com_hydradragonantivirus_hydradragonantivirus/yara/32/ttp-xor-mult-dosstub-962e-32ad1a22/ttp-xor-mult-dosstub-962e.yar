rule TTP_XOR_MULT_DOSStub_962e {
  strings:
    $key_962e = { c2 46 [2] b6 5e [2] f1 5c [2] b6 4d [2] f8 41 [2] f4 4b [2] e3 40 [2] f8 0e [2] c5 }

  condition:
    any of them
}
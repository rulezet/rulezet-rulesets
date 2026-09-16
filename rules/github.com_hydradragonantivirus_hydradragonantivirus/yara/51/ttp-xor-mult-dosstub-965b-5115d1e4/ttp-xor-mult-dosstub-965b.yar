rule TTP_XOR_MULT_DOSStub_965b {
  strings:
    $key_965b = { c2 33 [2] b6 2b [2] f1 29 [2] b6 38 [2] f8 34 [2] f4 3e [2] e3 35 [2] f8 7b [2] c5 }

  condition:
    any of them
}
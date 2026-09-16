rule TTP_XOR_MULT_DOSStub_964c {
  strings:
    $key_964c = { c2 24 [2] b6 3c [2] f1 3e [2] b6 2f [2] f8 23 [2] f4 29 [2] e3 22 [2] f8 6c [2] c5 }

  condition:
    any of them
}
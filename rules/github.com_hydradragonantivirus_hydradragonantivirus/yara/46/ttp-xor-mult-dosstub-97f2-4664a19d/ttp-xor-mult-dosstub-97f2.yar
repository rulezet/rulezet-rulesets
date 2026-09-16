rule TTP_XOR_MULT_DOSStub_97f2 {
  strings:
    $key_97f2 = { c3 9a [2] b7 82 [2] f0 80 [2] b7 91 [2] f9 9d [2] f5 97 [2] e2 9c [2] f9 d2 [2] c4 }

  condition:
    any of them
}
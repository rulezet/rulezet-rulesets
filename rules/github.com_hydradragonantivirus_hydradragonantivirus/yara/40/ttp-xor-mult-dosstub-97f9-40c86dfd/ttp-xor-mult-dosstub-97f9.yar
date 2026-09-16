rule TTP_XOR_MULT_DOSStub_97f9 {
  strings:
    $key_97f9 = { c3 91 [2] b7 89 [2] f0 8b [2] b7 9a [2] f9 96 [2] f5 9c [2] e2 97 [2] f9 d9 [2] c4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_85f2 {
  strings:
    $key_85f2 = { d1 9a [2] a5 82 [2] e2 80 [2] a5 91 [2] eb 9d [2] e7 97 [2] f0 9c [2] eb d2 [2] d6 }

  condition:
    any of them
}
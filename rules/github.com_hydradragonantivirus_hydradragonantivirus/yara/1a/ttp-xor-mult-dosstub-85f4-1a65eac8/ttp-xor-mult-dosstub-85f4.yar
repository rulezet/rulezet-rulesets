rule TTP_XOR_MULT_DOSStub_85f4 {
  strings:
    $key_85f4 = { d1 9c [2] a5 84 [2] e2 86 [2] a5 97 [2] eb 9b [2] e7 91 [2] f0 9a [2] eb d4 [2] d6 }

  condition:
    any of them
}
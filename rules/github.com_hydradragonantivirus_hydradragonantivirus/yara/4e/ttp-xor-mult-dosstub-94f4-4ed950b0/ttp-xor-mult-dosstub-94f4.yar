rule TTP_XOR_MULT_DOSStub_94f4 {
  strings:
    $key_94f4 = { c0 9c [2] b4 84 [2] f3 86 [2] b4 97 [2] fa 9b [2] f6 91 [2] e1 9a [2] fa d4 [2] c7 }

  condition:
    any of them
}
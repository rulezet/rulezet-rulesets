rule TTP_XOR_MULT_DOSStub_94e3 {
  strings:
    $key_94e3 = { c0 8b [2] b4 93 [2] f3 91 [2] b4 80 [2] fa 8c [2] f6 86 [2] e1 8d [2] fa c3 [2] c7 }

  condition:
    any of them
}
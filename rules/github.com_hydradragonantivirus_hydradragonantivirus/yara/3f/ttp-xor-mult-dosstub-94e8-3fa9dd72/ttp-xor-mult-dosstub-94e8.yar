rule TTP_XOR_MULT_DOSStub_94e8 {
  strings:
    $key_94e8 = { c0 80 [2] b4 98 [2] f3 9a [2] b4 8b [2] fa 87 [2] f6 8d [2] e1 86 [2] fa c8 [2] c7 }

  condition:
    any of them
}
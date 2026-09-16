rule TTP_XOR_MULT_DOSStub_91e9 {
  strings:
    $key_91e9 = { c5 81 [2] b1 99 [2] f6 9b [2] b1 8a [2] ff 86 [2] f3 8c [2] e4 87 [2] ff c9 [2] c2 }

  condition:
    any of them
}
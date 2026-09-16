rule TTP_XOR_MULT_DOSStub_8679 {
  strings:
    $key_8679 = { d2 11 [2] a6 09 [2] e1 0b [2] a6 1a [2] e8 16 [2] e4 1c [2] f3 17 [2] e8 59 [2] d5 }

  condition:
    any of them
}
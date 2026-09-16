rule TTP_XOR_MULT_DOSStub_83f7 {
  strings:
    $key_83f7 = { d7 9f [2] a3 87 [2] e4 85 [2] a3 94 [2] ed 98 [2] e1 92 [2] f6 99 [2] ed d7 [2] d0 }

  condition:
    any of them
}
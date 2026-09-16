rule TTP_XOR_MULT_DOSStub_8610 {
  strings:
    $key_8610 = { d2 78 [2] a6 60 [2] e1 62 [2] a6 73 [2] e8 7f [2] e4 75 [2] f3 7e [2] e8 30 [2] d5 }

  condition:
    any of them
}
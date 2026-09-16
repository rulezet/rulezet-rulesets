rule TTP_XOR_MULT_DOSStub_c5a6 {
  strings:
    $key_c5a6 = { 91 ce [2] e5 d6 [2] a2 d4 [2] e5 c5 [2] ab c9 [2] a7 c3 [2] b0 c8 [2] ab 86 [2] 96 }

  condition:
    any of them
}
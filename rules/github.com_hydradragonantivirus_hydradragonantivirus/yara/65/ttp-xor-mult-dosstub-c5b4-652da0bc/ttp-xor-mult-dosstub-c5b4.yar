rule TTP_XOR_MULT_DOSStub_c5b4 {
  strings:
    $key_c5b4 = { 91 dc [2] e5 c4 [2] a2 c6 [2] e5 d7 [2] ab db [2] a7 d1 [2] b0 da [2] ab 94 [2] 96 }

  condition:
    any of them
}
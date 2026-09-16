rule TTP_XOR_MULT_DOSStub_c570 {
  strings:
    $key_c570 = { 91 18 [2] e5 00 [2] a2 02 [2] e5 13 [2] ab 1f [2] a7 15 [2] b0 1e [2] ab 50 [2] 96 }

  condition:
    any of them
}
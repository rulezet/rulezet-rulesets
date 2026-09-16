rule TTP_XOR_MULT_DOSStub_c549 {
  strings:
    $key_c549 = { 91 21 [2] e5 39 [2] a2 3b [2] e5 2a [2] ab 26 [2] a7 2c [2] b0 27 [2] ab 69 [2] 96 }

  condition:
    any of them
}
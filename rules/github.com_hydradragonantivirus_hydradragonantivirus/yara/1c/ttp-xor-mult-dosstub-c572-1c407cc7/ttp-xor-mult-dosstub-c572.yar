rule TTP_XOR_MULT_DOSStub_c572 {
  strings:
    $key_c572 = { 91 1a [2] e5 02 [2] a2 00 [2] e5 11 [2] ab 1d [2] a7 17 [2] b0 1c [2] ab 52 [2] 96 }

  condition:
    any of them
}
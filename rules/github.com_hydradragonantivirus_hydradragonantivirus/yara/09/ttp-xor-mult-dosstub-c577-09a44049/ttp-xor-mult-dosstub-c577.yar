rule TTP_XOR_MULT_DOSStub_c577 {
  strings:
    $key_c577 = { 91 1f [2] e5 07 [2] a2 05 [2] e5 14 [2] ab 18 [2] a7 12 [2] b0 19 [2] ab 57 [2] 96 }

  condition:
    any of them
}
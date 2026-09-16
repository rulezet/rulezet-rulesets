rule TTP_XOR_MULT_DOSStub_c576 {
  strings:
    $key_c576 = { 91 1e [2] e5 06 [2] a2 04 [2] e5 15 [2] ab 19 [2] a7 13 [2] b0 18 [2] ab 56 [2] 96 }

  condition:
    any of them
}
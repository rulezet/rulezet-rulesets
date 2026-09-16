rule TTP_XOR_MULT_DOSStub_c5c0 {
  strings:
    $key_c5c0 = { 91 a8 [2] e5 b0 [2] a2 b2 [2] e5 a3 [2] ab af [2] a7 a5 [2] b0 ae [2] ab e0 [2] 96 }

  condition:
    any of them
}
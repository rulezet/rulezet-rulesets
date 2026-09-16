rule TTP_XOR_MULT_DOSStub_c5c8 {
  strings:
    $key_c5c8 = { 91 a0 [2] e5 b8 [2] a2 ba [2] e5 ab [2] ab a7 [2] a7 ad [2] b0 a6 [2] ab e8 [2] 96 }

  condition:
    any of them
}
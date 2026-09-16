rule TTP_XOR_MULT_DOSStub_c0cb {
  strings:
    $key_c0cb = { 94 a3 [2] e0 bb [2] a7 b9 [2] e0 a8 [2] ae a4 [2] a2 ae [2] b5 a5 [2] ae eb [2] 93 }

  condition:
    any of them
}
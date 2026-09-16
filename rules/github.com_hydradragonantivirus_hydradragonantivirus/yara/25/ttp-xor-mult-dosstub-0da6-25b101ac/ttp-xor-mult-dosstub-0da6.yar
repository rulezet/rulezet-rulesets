rule TTP_XOR_MULT_DOSStub_0da6 {
  strings:
    $key_0da6 = { 59 ce [2] 2d d6 [2] 6a d4 [2] 2d c5 [2] 63 c9 [2] 6f c3 [2] 78 c8 [2] 63 86 [2] 5e }

  condition:
    any of them
}
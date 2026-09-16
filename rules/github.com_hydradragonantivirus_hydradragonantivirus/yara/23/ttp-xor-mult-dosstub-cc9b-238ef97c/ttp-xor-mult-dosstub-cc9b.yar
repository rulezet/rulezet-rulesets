rule TTP_XOR_MULT_DOSStub_cc9b {
  strings:
    $key_cc9b = { 98 f3 [2] ec eb [2] ab e9 [2] ec f8 [2] a2 f4 [2] ae fe [2] b9 f5 [2] a2 bb [2] 9f }

  condition:
    any of them
}
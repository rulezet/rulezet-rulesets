rule TTP_XOR_MULT_DOSStub_d69b {
  strings:
    $key_d69b = { 82 f3 [2] f6 eb [2] b1 e9 [2] f6 f8 [2] b8 f4 [2] b4 fe [2] a3 f5 [2] b8 bb [2] 85 }

  condition:
    any of them
}
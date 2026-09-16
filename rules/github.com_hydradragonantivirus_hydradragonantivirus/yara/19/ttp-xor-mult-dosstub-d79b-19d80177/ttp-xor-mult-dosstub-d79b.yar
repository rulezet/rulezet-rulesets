rule TTP_XOR_MULT_DOSStub_d79b {
  strings:
    $key_d79b = { 83 f3 [2] f7 eb [2] b0 e9 [2] f7 f8 [2] b9 f4 [2] b5 fe [2] a2 f5 [2] b9 bb [2] 84 }

  condition:
    any of them
}
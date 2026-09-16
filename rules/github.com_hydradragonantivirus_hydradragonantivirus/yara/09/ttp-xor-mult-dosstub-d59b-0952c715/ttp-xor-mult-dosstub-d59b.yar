rule TTP_XOR_MULT_DOSStub_d59b {
  strings:
    $key_d59b = { 81 f3 [2] f5 eb [2] b2 e9 [2] f5 f8 [2] bb f4 [2] b7 fe [2] a0 f5 [2] bb bb [2] 86 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7385 {
  strings:
    $key_7385 = { 27 ed [2] 53 f5 [2] 14 f7 [2] 53 e6 [2] 1d ea [2] 11 e0 [2] 06 eb [2] 1d a5 [2] 20 }

  condition:
    any of them
}
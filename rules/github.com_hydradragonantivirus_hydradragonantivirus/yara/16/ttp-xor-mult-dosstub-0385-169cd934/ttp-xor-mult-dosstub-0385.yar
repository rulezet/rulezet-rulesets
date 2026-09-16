rule TTP_XOR_MULT_DOSStub_0385 {
  strings:
    $key_0385 = { 57 ed [2] 23 f5 [2] 64 f7 [2] 23 e6 [2] 6d ea [2] 61 e0 [2] 76 eb [2] 6d a5 [2] 50 }

  condition:
    any of them
}
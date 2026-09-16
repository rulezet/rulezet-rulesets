rule TTP_XOR_MULT_DOSStub_7085 {
  strings:
    $key_7085 = { 24 ed [2] 50 f5 [2] 17 f7 [2] 50 e6 [2] 1e ea [2] 12 e0 [2] 05 eb [2] 1e a5 [2] 23 }

  condition:
    any of them
}
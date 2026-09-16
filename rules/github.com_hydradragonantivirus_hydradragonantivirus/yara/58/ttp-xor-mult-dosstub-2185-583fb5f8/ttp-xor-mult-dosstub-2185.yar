rule TTP_XOR_MULT_DOSStub_2185 {
  strings:
    $key_2185 = { 75 ed [2] 01 f5 [2] 46 f7 [2] 01 e6 [2] 4f ea [2] 43 e0 [2] 54 eb [2] 4f a5 [2] 72 }

  condition:
    any of them
}
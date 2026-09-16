rule TTP_XOR_MULT_DOSStub_e485 {
  strings:
    $key_e485 = { b0 ed [2] c4 f5 [2] 83 f7 [2] c4 e6 [2] 8a ea [2] 86 e0 [2] 91 eb [2] 8a a5 [2] b7 }

  condition:
    any of them
}
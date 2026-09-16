rule TTP_XOR_MULT_DOSStub_e085 {
  strings:
    $key_e085 = { b4 ed [2] c0 f5 [2] 87 f7 [2] c0 e6 [2] 8e ea [2] 82 e0 [2] 95 eb [2] 8e a5 [2] b3 }

  condition:
    any of them
}
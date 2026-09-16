rule TTP_XOR_MULT_DOSStub_3685 {
  strings:
    $key_3685 = { 62 ed [2] 16 f5 [2] 51 f7 [2] 16 e6 [2] 58 ea [2] 54 e0 [2] 43 eb [2] 58 a5 [2] 65 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0685 {
  strings:
    $key_0685 = { 52 ed [2] 26 f5 [2] 61 f7 [2] 26 e6 [2] 68 ea [2] 64 e0 [2] 73 eb [2] 68 a5 [2] 55 }

  condition:
    any of them
}
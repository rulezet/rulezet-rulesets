rule TTP_XOR_MULT_DOSStub_4485 {
  strings:
    $key_4485 = { 10 ed [2] 64 f5 [2] 23 f7 [2] 64 e6 [2] 2a ea [2] 26 e0 [2] 31 eb [2] 2a a5 [2] 17 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7485 {
  strings:
    $key_7485 = { 20 ed [2] 54 f5 [2] 13 f7 [2] 54 e6 [2] 1a ea [2] 16 e0 [2] 01 eb [2] 1a a5 [2] 27 }

  condition:
    any of them
}
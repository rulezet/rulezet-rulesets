rule TTP_XOR_MULT_DOSStub_0ec8 {
  strings:
    $key_0ec8 = { 5a a0 [2] 2e b8 [2] 69 ba [2] 2e ab [2] 60 a7 [2] 6c ad [2] 7b a6 [2] 60 e8 [2] 5d }

  condition:
    any of them
}
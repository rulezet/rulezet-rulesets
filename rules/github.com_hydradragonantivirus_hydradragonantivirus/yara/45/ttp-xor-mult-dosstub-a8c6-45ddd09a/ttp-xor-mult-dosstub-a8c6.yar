rule TTP_XOR_MULT_DOSStub_a8c6 {
  strings:
    $key_a8c6 = { fc ae [2] 88 b6 [2] cf b4 [2] 88 a5 [2] c6 a9 [2] ca a3 [2] dd a8 [2] c6 e6 [2] fb }

  condition:
    any of them
}
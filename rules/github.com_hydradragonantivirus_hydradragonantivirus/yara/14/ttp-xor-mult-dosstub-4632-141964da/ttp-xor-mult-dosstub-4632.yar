rule TTP_XOR_MULT_DOSStub_4632 {
  strings:
    $key_4632 = { 12 5a [2] 66 42 [2] 21 40 [2] 66 51 [2] 28 5d [2] 24 57 [2] 33 5c [2] 28 12 [2] 15 }

  condition:
    any of them
}
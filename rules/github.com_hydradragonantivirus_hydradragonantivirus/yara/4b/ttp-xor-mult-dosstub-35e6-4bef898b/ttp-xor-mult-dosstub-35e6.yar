rule TTP_XOR_MULT_DOSStub_35e6 {
  strings:
    $key_35e6 = { 61 8e [2] 15 96 [2] 52 94 [2] 15 85 [2] 5b 89 [2] 57 83 [2] 40 88 [2] 5b c6 [2] 66 }

  condition:
    any of them
}
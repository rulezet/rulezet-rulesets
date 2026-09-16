rule TTP_XOR_MULT_DOSStub_77f5 {
  strings:
    $key_77f5 = { 23 9d [2] 57 85 [2] 10 87 [2] 57 96 [2] 19 9a [2] 15 90 [2] 02 9b [2] 19 d5 [2] 24 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_4109 {
  strings:
    $key_4109 = { 15 61 [2] 61 79 [2] 26 7b [2] 61 6a [2] 2f 66 [2] 23 6c [2] 34 67 [2] 2f 29 [2] 12 }

  condition:
    any of them
}
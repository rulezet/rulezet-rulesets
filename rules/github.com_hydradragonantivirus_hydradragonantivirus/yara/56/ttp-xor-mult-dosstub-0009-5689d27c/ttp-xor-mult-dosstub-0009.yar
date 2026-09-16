rule TTP_XOR_MULT_DOSStub_0009 {
  strings:
    $key_0009 = { 54 61 [2] 20 79 [2] 67 7b [2] 20 6a [2] 6e 66 [2] 62 6c [2] 75 67 [2] 6e 29 [2] 53 }

  condition:
    any of them
}
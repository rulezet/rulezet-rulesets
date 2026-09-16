rule TTP_XOR_MULT_DOSStub_0032 {
  strings:
    $key_0032 = { 54 5a [2] 20 42 [2] 67 40 [2] 20 51 [2] 6e 5d [2] 62 57 [2] 75 5c [2] 6e 12 [2] 53 }

  condition:
    any of them
}
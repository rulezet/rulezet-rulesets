rule TTP_XOR_MULT_DOSStub_0059 {
  strings:
    $key_0059 = { 54 31 [2] 20 29 [2] 67 2b [2] 20 3a [2] 6e 36 [2] 62 3c [2] 75 37 [2] 6e 79 [2] 53 }

  condition:
    any of them
}
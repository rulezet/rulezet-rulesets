rule TTP_XOR_MULT_DOSStub_7509 {
  strings:
    $key_7509 = { 21 61 [2] 55 79 [2] 12 7b [2] 55 6a [2] 1b 66 [2] 17 6c [2] 00 67 [2] 1b 29 [2] 26 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_351a {
  strings:
    $key_351a = { 61 72 [2] 15 6a [2] 52 68 [2] 15 79 [2] 5b 75 [2] 57 7f [2] 40 74 [2] 5b 3a [2] 66 }

  condition:
    any of them
}
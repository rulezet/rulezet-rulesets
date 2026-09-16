rule TTP_XOR_MULT_DOSStub_3a99 {
  strings:
    $key_3a99 = { 6e f1 [2] 1a e9 [2] 5d eb [2] 1a fa [2] 54 f6 [2] 58 fc [2] 4f f7 [2] 54 b9 [2] 69 }

  condition:
    any of them
}
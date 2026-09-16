rule TTP_XOR_MULT_DOSStub_1a99 {
  strings:
    $key_1a99 = { 4e f1 [2] 3a e9 [2] 7d eb [2] 3a fa [2] 74 f6 [2] 78 fc [2] 6f f7 [2] 74 b9 [2] 49 }

  condition:
    any of them
}
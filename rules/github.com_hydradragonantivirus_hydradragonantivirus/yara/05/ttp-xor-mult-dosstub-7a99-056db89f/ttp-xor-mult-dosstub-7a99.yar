rule TTP_XOR_MULT_DOSStub_7a99 {
  strings:
    $key_7a99 = { 2e f1 [2] 5a e9 [2] 1d eb [2] 5a fa [2] 14 f6 [2] 18 fc [2] 0f f7 [2] 14 b9 [2] 29 }

  condition:
    any of them
}
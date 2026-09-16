rule TTP_XOR_MULT_DOSStub_6a99 {
  strings:
    $key_6a99 = { 3e f1 [2] 4a e9 [2] 0d eb [2] 4a fa [2] 04 f6 [2] 08 fc [2] 1f f7 [2] 04 b9 [2] 39 }

  condition:
    any of them
}
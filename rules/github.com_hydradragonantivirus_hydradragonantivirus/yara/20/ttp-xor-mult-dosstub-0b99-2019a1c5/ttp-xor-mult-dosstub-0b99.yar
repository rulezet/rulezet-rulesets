rule TTP_XOR_MULT_DOSStub_0b99 {
  strings:
    $key_0b99 = { 5f f1 [2] 2b e9 [2] 6c eb [2] 2b fa [2] 65 f6 [2] 69 fc [2] 7e f7 [2] 65 b9 [2] 58 }

  condition:
    any of them
}
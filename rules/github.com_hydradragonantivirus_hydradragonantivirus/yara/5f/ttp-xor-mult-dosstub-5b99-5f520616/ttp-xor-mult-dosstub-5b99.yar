rule TTP_XOR_MULT_DOSStub_5b99 {
  strings:
    $key_5b99 = { 0f f1 [2] 7b e9 [2] 3c eb [2] 7b fa [2] 35 f6 [2] 39 fc [2] 2e f7 [2] 35 b9 [2] 08 }

  condition:
    any of them
}
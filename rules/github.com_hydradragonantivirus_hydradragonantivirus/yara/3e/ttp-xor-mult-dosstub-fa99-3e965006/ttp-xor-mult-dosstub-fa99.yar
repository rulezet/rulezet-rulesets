rule TTP_XOR_MULT_DOSStub_fa99 {
  strings:
    $key_fa99 = { ae f1 [2] da e9 [2] 9d eb [2] da fa [2] 94 f6 [2] 98 fc [2] 8f f7 [2] 94 b9 [2] a9 }

  condition:
    any of them
}
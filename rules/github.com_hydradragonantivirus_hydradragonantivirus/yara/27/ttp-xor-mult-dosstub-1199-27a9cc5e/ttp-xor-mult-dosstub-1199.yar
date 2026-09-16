rule TTP_XOR_MULT_DOSStub_1199 {
  strings:
    $key_1199 = { 45 f1 [2] 31 e9 [2] 76 eb [2] 31 fa [2] 7f f6 [2] 73 fc [2] 64 f7 [2] 7f b9 [2] 42 }

  condition:
    any of them
}
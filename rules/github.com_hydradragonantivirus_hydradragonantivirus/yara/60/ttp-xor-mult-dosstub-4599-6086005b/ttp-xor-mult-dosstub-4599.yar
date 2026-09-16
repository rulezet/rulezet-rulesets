rule TTP_XOR_MULT_DOSStub_4599 {
  strings:
    $key_4599 = { 11 f1 [2] 65 e9 [2] 22 eb [2] 65 fa [2] 2b f6 [2] 27 fc [2] 30 f7 [2] 2b b9 [2] 16 }

  condition:
    any of them
}
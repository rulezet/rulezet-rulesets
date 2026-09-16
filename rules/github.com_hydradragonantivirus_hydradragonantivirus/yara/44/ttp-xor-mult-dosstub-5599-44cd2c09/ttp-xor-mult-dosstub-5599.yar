rule TTP_XOR_MULT_DOSStub_5599 {
  strings:
    $key_5599 = { 01 f1 [2] 75 e9 [2] 32 eb [2] 75 fa [2] 3b f6 [2] 37 fc [2] 20 f7 [2] 3b b9 [2] 06 }

  condition:
    any of them
}
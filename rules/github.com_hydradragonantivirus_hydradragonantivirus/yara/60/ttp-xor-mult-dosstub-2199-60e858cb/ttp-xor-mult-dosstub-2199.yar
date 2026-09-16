rule TTP_XOR_MULT_DOSStub_2199 {
  strings:
    $key_2199 = { 75 f1 [2] 01 e9 [2] 46 eb [2] 01 fa [2] 4f f6 [2] 43 fc [2] 54 f7 [2] 4f b9 [2] 72 }

  condition:
    any of them
}
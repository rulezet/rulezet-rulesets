rule TTP_XOR_MULT_DOSStub_6799 {
  strings:
    $key_6799 = { 33 f1 [2] 47 e9 [2] 00 eb [2] 47 fa [2] 09 f6 [2] 05 fc [2] 12 f7 [2] 09 b9 [2] 34 }

  condition:
    any of them
}
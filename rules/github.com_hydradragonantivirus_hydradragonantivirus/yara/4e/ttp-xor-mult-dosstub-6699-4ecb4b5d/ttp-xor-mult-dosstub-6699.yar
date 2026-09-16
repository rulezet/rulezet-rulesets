rule TTP_XOR_MULT_DOSStub_6699 {
  strings:
    $key_6699 = { 32 f1 [2] 46 e9 [2] 01 eb [2] 46 fa [2] 08 f6 [2] 04 fc [2] 13 f7 [2] 08 b9 [2] 35 }

  condition:
    any of them
}
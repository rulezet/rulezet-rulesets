rule TTP_XOR_MULT_DOSStub_3699 {
  strings:
    $key_3699 = { 62 f1 [2] 16 e9 [2] 51 eb [2] 16 fa [2] 58 f6 [2] 54 fc [2] 43 f7 [2] 58 b9 [2] 65 }

  condition:
    any of them
}
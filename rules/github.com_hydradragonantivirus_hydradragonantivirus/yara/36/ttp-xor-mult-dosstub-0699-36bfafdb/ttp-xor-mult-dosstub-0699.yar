rule TTP_XOR_MULT_DOSStub_0699 {
  strings:
    $key_0699 = { 52 f1 [2] 26 e9 [2] 61 eb [2] 26 fa [2] 68 f6 [2] 64 fc [2] 73 f7 [2] 68 b9 [2] 55 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6099 {
  strings:
    $key_6099 = { 34 f1 [2] 40 e9 [2] 07 eb [2] 40 fa [2] 0e f6 [2] 02 fc [2] 15 f7 [2] 0e b9 [2] 33 }

  condition:
    any of them
}
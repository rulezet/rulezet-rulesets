rule TTP_XOR_MULT_DOSStub_4099 {
  strings:
    $key_4099 = { 14 f1 [2] 60 e9 [2] 27 eb [2] 60 fa [2] 2e f6 [2] 22 fc [2] 35 f7 [2] 2e b9 [2] 13 }

  condition:
    any of them
}
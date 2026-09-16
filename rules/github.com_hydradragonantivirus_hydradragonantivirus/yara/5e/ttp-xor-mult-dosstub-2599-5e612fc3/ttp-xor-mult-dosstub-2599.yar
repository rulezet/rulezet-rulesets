rule TTP_XOR_MULT_DOSStub_2599 {
  strings:
    $key_2599 = { 71 f1 [2] 05 e9 [2] 42 eb [2] 05 fa [2] 4b f6 [2] 47 fc [2] 50 f7 [2] 4b b9 [2] 76 }

  condition:
    any of them
}
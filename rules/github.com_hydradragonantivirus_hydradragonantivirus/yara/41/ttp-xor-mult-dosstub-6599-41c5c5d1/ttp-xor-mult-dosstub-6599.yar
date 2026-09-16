rule TTP_XOR_MULT_DOSStub_6599 {
  strings:
    $key_6599 = { 31 f1 [2] 45 e9 [2] 02 eb [2] 45 fa [2] 0b f6 [2] 07 fc [2] 10 f7 [2] 0b b9 [2] 36 }

  condition:
    any of them
}
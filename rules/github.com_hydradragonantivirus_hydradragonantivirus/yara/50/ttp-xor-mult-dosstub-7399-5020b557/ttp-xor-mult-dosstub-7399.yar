rule TTP_XOR_MULT_DOSStub_7399 {
  strings:
    $key_7399 = { 27 f1 [2] 53 e9 [2] 14 eb [2] 53 fa [2] 1d f6 [2] 11 fc [2] 06 f7 [2] 1d b9 [2] 20 }

  condition:
    any of them
}
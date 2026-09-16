rule TTP_XOR_MULT_DOSStub_f899 {
  strings:
    $key_f899 = { ac f1 [2] d8 e9 [2] 9f eb [2] d8 fa [2] 96 f6 [2] 9a fc [2] 8d f7 [2] 96 b9 [2] ab }

  condition:
    any of them
}
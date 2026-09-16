rule TTP_XOR_MULT_DOSStub_f897 {
  strings:
    $key_f897 = { ac ff [2] d8 e7 [2] 9f e5 [2] d8 f4 [2] 96 f8 [2] 9a f2 [2] 8d f9 [2] 96 b7 [2] ab }

  condition:
    any of them
}
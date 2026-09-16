rule TTP_XOR_MULT_DOSStub_0e97 {
  strings:
    $key_0e97 = { 5a ff [2] 2e e7 [2] 69 e5 [2] 2e f4 [2] 60 f8 [2] 6c f2 [2] 7b f9 [2] 60 b7 [2] 5d }

  condition:
    any of them
}
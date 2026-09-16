rule TTP_XOR_MULT_DOSStub_5e97 {
  strings:
    $key_5e97 = { 0a ff [2] 7e e7 [2] 39 e5 [2] 7e f4 [2] 30 f8 [2] 3c f2 [2] 2b f9 [2] 30 b7 [2] 0d }

  condition:
    any of them
}
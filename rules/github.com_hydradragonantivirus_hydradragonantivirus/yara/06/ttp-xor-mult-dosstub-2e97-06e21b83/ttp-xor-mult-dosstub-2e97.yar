rule TTP_XOR_MULT_DOSStub_2e97 {
  strings:
    $key_2e97 = { 7a ff [2] 0e e7 [2] 49 e5 [2] 0e f4 [2] 40 f8 [2] 4c f2 [2] 5b f9 [2] 40 b7 [2] 7d }

  condition:
    any of them
}
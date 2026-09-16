rule TTP_XOR_MULT_DOSStub_7397 {
  strings:
    $key_7397 = { 27 ff [2] 53 e7 [2] 14 e5 [2] 53 f4 [2] 1d f8 [2] 11 f2 [2] 06 f9 [2] 1d b7 [2] 20 }

  condition:
    any of them
}
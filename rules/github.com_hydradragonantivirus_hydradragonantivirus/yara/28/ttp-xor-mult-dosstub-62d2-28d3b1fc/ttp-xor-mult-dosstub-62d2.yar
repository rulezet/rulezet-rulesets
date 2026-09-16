rule TTP_XOR_MULT_DOSStub_62d2 {
  strings:
    $key_62d2 = { 36 ba [2] 42 a2 [2] 05 a0 [2] 42 b1 [2] 0c bd [2] 00 b7 [2] 17 bc [2] 0c f2 [2] 31 }

  condition:
    any of them
}
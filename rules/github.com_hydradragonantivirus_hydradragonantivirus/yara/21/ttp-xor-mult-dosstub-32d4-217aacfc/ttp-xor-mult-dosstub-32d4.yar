rule TTP_XOR_MULT_DOSStub_32d4 {
  strings:
    $key_32d4 = { 66 bc [2] 12 a4 [2] 55 a6 [2] 12 b7 [2] 5c bb [2] 50 b1 [2] 47 ba [2] 5c f4 [2] 61 }

  condition:
    any of them
}
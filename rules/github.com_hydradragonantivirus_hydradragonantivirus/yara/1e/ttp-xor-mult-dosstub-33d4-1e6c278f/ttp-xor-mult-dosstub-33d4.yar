rule TTP_XOR_MULT_DOSStub_33d4 {
  strings:
    $key_33d4 = { 67 bc [2] 13 a4 [2] 54 a6 [2] 13 b7 [2] 5d bb [2] 51 b1 [2] 46 ba [2] 5d f4 [2] 60 }

  condition:
    any of them
}
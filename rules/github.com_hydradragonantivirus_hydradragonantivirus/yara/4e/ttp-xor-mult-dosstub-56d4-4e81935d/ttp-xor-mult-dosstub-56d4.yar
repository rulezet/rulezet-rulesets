rule TTP_XOR_MULT_DOSStub_56d4 {
  strings:
    $key_56d4 = { 02 bc [2] 76 a4 [2] 31 a6 [2] 76 b7 [2] 38 bb [2] 34 b1 [2] 23 ba [2] 38 f4 [2] 05 }

  condition:
    any of them
}
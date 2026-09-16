rule TTP_XOR_MULT_DOSStub_27d4 {
  strings:
    $key_27d4 = { 73 bc [2] 07 a4 [2] 40 a6 [2] 07 b7 [2] 49 bb [2] 45 b1 [2] 52 ba [2] 49 f4 [2] 74 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_27d9 {
  strings:
    $key_27d9 = { 73 b1 [2] 07 a9 [2] 40 ab [2] 07 ba [2] 49 b6 [2] 45 bc [2] 52 b7 [2] 49 f9 [2] 74 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_19d4 {
  strings:
    $key_19d4 = { 4d bc [2] 39 a4 [2] 7e a6 [2] 39 b7 [2] 77 bb [2] 7b b1 [2] 6c ba [2] 77 f4 [2] 4a }

  condition:
    any of them
}
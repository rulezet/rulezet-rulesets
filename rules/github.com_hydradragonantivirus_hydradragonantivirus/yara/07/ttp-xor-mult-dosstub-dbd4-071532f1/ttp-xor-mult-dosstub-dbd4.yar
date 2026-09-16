rule TTP_XOR_MULT_DOSStub_dbd4 {
  strings:
    $key_dbd4 = { 8f bc [2] fb a4 [2] bc a6 [2] fb b7 [2] b5 bb [2] b9 b1 [2] ae ba [2] b5 f4 [2] 88 }

  condition:
    any of them
}
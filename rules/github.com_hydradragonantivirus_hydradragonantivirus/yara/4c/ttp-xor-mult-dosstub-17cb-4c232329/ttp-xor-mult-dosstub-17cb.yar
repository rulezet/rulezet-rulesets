rule TTP_XOR_MULT_DOSStub_17cb {
  strings:
    $key_17cb = { 43 a3 [2] 37 bb [2] 70 b9 [2] 37 a8 [2] 79 a4 [2] 75 ae [2] 62 a5 [2] 79 eb [2] 44 }

  condition:
    any of them
}
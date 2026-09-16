rule TTP_XOR_MULT_DOSStub_36cb {
  strings:
    $key_36cb = { 62 a3 [2] 16 bb [2] 51 b9 [2] 16 a8 [2] 58 a4 [2] 54 ae [2] 43 a5 [2] 58 eb [2] 65 }

  condition:
    any of them
}
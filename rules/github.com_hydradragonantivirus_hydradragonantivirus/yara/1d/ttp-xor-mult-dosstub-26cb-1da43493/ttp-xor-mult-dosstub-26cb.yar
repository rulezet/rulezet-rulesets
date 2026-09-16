rule TTP_XOR_MULT_DOSStub_26cb {
  strings:
    $key_26cb = { 72 a3 [2] 06 bb [2] 41 b9 [2] 06 a8 [2] 48 a4 [2] 44 ae [2] 53 a5 [2] 48 eb [2] 75 }

  condition:
    any of them
}
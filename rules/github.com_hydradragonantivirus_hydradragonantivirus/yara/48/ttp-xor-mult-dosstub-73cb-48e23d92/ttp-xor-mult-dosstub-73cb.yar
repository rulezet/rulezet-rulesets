rule TTP_XOR_MULT_DOSStub_73cb {
  strings:
    $key_73cb = { 27 a3 [2] 53 bb [2] 14 b9 [2] 53 a8 [2] 1d a4 [2] 11 ae [2] 06 a5 [2] 1d eb [2] 20 }

  condition:
    any of them
}
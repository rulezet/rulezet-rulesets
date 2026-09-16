rule TTP_XOR_MULT_DOSStub_74cb {
  strings:
    $key_74cb = { 20 a3 [2] 54 bb [2] 13 b9 [2] 54 a8 [2] 1a a4 [2] 16 ae [2] 01 a5 [2] 1a eb [2] 27 }

  condition:
    any of them
}
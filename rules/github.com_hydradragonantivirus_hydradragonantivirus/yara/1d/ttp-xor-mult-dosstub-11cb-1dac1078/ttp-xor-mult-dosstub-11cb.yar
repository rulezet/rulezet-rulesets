rule TTP_XOR_MULT_DOSStub_11cb {
  strings:
    $key_11cb = { 45 a3 [2] 31 bb [2] 76 b9 [2] 31 a8 [2] 7f a4 [2] 73 ae [2] 64 a5 [2] 7f eb [2] 42 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_59cb {
  strings:
    $key_59cb = { 0d a3 [2] 79 bb [2] 3e b9 [2] 79 a8 [2] 37 a4 [2] 3b ae [2] 2c a5 [2] 37 eb [2] 0a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_09cb {
  strings:
    $key_09cb = { 5d a3 [2] 29 bb [2] 6e b9 [2] 29 a8 [2] 67 a4 [2] 6b ae [2] 7c a5 [2] 67 eb [2] 5a }

  condition:
    any of them
}
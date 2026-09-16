rule TTP_XOR_MULT_DOSStub_79cb {
  strings:
    $key_79cb = { 2d a3 [2] 59 bb [2] 1e b9 [2] 59 a8 [2] 17 a4 [2] 1b ae [2] 0c a5 [2] 17 eb [2] 2a }

  condition:
    any of them
}
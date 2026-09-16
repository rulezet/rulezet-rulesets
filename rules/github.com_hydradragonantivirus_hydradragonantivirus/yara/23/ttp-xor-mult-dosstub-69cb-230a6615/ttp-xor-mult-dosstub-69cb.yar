rule TTP_XOR_MULT_DOSStub_69cb {
  strings:
    $key_69cb = { 3d a3 [2] 49 bb [2] 0e b9 [2] 49 a8 [2] 07 a4 [2] 0b ae [2] 1c a5 [2] 07 eb [2] 3a }

  condition:
    any of them
}
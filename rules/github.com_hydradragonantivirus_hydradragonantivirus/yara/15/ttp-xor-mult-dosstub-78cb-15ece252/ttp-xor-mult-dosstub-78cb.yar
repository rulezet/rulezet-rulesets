rule TTP_XOR_MULT_DOSStub_78cb {
  strings:
    $key_78cb = { 2c a3 [2] 58 bb [2] 1f b9 [2] 58 a8 [2] 16 a4 [2] 1a ae [2] 0d a5 [2] 16 eb [2] 2b }

  condition:
    any of them
}
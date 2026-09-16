rule TTP_XOR_MULT_DOSStub_08cb {
  strings:
    $key_08cb = { 5c a3 [2] 28 bb [2] 6f b9 [2] 28 a8 [2] 66 a4 [2] 6a ae [2] 7d a5 [2] 66 eb [2] 5b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_28cb {
  strings:
    $key_28cb = { 7c a3 [2] 08 bb [2] 4f b9 [2] 08 a8 [2] 46 a4 [2] 4a ae [2] 5d a5 [2] 46 eb [2] 7b }

  condition:
    any of them
}
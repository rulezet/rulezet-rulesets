rule TTP_XOR_MULT_DOSStub_38cb {
  strings:
    $key_38cb = { 6c a3 [2] 18 bb [2] 5f b9 [2] 18 a8 [2] 56 a4 [2] 5a ae [2] 4d a5 [2] 56 eb [2] 6b }

  condition:
    any of them
}
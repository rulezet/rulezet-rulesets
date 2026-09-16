rule TTP_XOR_MULT_DOSStub_3980 {
  strings:
    $key_3980 = { 6d e8 [2] 19 f0 [2] 5e f2 [2] 19 e3 [2] 57 ef [2] 5b e5 [2] 4c ee [2] 57 a0 [2] 6a }

  condition:
    any of them
}
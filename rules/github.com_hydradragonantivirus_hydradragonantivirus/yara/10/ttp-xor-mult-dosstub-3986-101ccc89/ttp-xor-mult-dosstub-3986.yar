rule TTP_XOR_MULT_DOSStub_3986 {
  strings:
    $key_3986 = { 6d ee [2] 19 f6 [2] 5e f4 [2] 19 e5 [2] 57 e9 [2] 5b e3 [2] 4c e8 [2] 57 a6 [2] 6a }

  condition:
    any of them
}
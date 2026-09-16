rule TTP_XOR_MULT_DOSStub_0f8d {
  strings:
    $key_0f8d = { 5b e5 [2] 2f fd [2] 68 ff [2] 2f ee [2] 61 e2 [2] 6d e8 [2] 7a e3 [2] 61 ad [2] 5c }

  condition:
    any of them
}
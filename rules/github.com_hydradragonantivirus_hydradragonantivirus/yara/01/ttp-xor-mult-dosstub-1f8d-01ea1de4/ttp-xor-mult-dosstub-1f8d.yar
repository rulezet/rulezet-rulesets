rule TTP_XOR_MULT_DOSStub_1f8d {
  strings:
    $key_1f8d = { 4b e5 [2] 3f fd [2] 78 ff [2] 3f ee [2] 71 e2 [2] 7d e8 [2] 6a e3 [2] 71 ad [2] 4c }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5f8d {
  strings:
    $key_5f8d = { 0b e5 [2] 7f fd [2] 38 ff [2] 7f ee [2] 31 e2 [2] 3d e8 [2] 2a e3 [2] 31 ad [2] 0c }

  condition:
    any of them
}
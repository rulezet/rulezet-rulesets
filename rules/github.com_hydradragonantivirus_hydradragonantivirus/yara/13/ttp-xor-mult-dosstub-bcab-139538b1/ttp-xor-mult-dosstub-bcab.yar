rule TTP_XOR_MULT_DOSStub_bcab {
  strings:
    $key_bcab = { e8 c3 [2] 9c db [2] db d9 [2] 9c c8 [2] d2 c4 [2] de ce [2] c9 c5 [2] d2 8b [2] ef }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_758d {
  strings:
    $key_758d = { 21 e5 [2] 55 fd [2] 12 ff [2] 55 ee [2] 1b e2 [2] 17 e8 [2] 00 e3 [2] 1b ad [2] 26 }

  condition:
    any of them
}
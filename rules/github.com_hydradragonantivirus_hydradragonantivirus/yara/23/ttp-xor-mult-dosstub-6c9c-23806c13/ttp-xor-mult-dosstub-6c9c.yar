rule TTP_XOR_MULT_DOSStub_6c9c {
  strings:
    $key_6c9c = { 38 f4 [2] 4c ec [2] 0b ee [2] 4c ff [2] 02 f3 [2] 0e f9 [2] 19 f2 [2] 02 bc [2] 3f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7c9c {
  strings:
    $key_7c9c = { 28 f4 [2] 5c ec [2] 1b ee [2] 5c ff [2] 12 f3 [2] 1e f9 [2] 09 f2 [2] 12 bc [2] 2f }

  condition:
    any of them
}
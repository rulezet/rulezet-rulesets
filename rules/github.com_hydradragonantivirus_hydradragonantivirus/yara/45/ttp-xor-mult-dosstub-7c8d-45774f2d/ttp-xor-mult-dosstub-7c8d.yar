rule TTP_XOR_MULT_DOSStub_7c8d {
  strings:
    $key_7c8d = { 28 e5 [2] 5c fd [2] 1b ff [2] 5c ee [2] 12 e2 [2] 1e e8 [2] 09 e3 [2] 12 ad [2] 2f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0c8d {
  strings:
    $key_0c8d = { 58 e5 [2] 2c fd [2] 6b ff [2] 2c ee [2] 62 e2 [2] 6e e8 [2] 79 e3 [2] 62 ad [2] 5f }

  condition:
    any of them
}
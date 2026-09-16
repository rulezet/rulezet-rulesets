rule TTP_XOR_MULT_DOSStub_6c8d {
  strings:
    $key_6c8d = { 38 e5 [2] 4c fd [2] 0b ff [2] 4c ee [2] 02 e2 [2] 0e e8 [2] 19 e3 [2] 02 ad [2] 3f }

  condition:
    any of them
}
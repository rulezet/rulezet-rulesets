rule TTP_XOR_MULT_DOSStub_3c8d {
  strings:
    $key_3c8d = { 68 e5 [2] 1c fd [2] 5b ff [2] 1c ee [2] 52 e2 [2] 5e e8 [2] 49 e3 [2] 52 ad [2] 6f }

  condition:
    any of them
}
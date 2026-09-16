rule TTP_XOR_MULT_DOSStub_2c8d {
  strings:
    $key_2c8d = { 78 e5 [2] 0c fd [2] 4b ff [2] 0c ee [2] 42 e2 [2] 4e e8 [2] 59 e3 [2] 42 ad [2] 7f }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_509e {
  strings:
    $key_509e = { 04 f6 [2] 70 ee [2] 37 ec [2] 70 fd [2] 3e f1 [2] 32 fb [2] 25 f0 [2] 3e be [2] 03 }

  condition:
    any of them
}
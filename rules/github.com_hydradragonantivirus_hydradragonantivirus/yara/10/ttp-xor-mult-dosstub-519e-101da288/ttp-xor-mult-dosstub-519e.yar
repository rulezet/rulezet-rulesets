rule TTP_XOR_MULT_DOSStub_519e {
  strings:
    $key_519e = { 05 f6 [2] 71 ee [2] 36 ec [2] 71 fd [2] 3f f1 [2] 33 fb [2] 24 f0 [2] 3f be [2] 02 }

  condition:
    any of them
}
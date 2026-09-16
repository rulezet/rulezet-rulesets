rule TTP_XOR_MULT_DOSStub_059e {
  strings:
    $key_059e = { 51 f6 [2] 25 ee [2] 62 ec [2] 25 fd [2] 6b f1 [2] 67 fb [2] 70 f0 [2] 6b be [2] 56 }

  condition:
    any of them
}
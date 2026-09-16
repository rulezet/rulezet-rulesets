rule TTP_XOR_MULT_DOSStub_119e {
  strings:
    $key_119e = { 45 f6 [2] 31 ee [2] 76 ec [2] 31 fd [2] 7f f1 [2] 73 fb [2] 64 f0 [2] 7f be [2] 42 }

  condition:
    any of them
}
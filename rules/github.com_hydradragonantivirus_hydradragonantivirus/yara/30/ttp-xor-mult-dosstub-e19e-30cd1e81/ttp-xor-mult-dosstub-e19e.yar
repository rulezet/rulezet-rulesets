rule TTP_XOR_MULT_DOSStub_e19e {
  strings:
    $key_e19e = { b5 f6 [2] c1 ee [2] 86 ec [2] c1 fd [2] 8f f1 [2] 83 fb [2] 94 f0 [2] 8f be [2] b2 }

  condition:
    any of them
}
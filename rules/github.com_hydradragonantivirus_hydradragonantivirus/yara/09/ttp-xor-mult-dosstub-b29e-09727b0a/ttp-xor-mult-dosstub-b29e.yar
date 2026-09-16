rule TTP_XOR_MULT_DOSStub_b29e {
  strings:
    $key_b29e = { e6 f6 [2] 92 ee [2] d5 ec [2] 92 fd [2] dc f1 [2] d0 fb [2] c7 f0 [2] dc be [2] e1 }

  condition:
    any of them
}
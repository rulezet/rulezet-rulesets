rule TTP_XOR_MULT_DOSStub_b293 {
  strings:
    $key_b293 = { e6 fb [2] 92 e3 [2] d5 e1 [2] 92 f0 [2] dc fc [2] d0 f6 [2] c7 fd [2] dc b3 [2] e1 }

  condition:
    any of them
}
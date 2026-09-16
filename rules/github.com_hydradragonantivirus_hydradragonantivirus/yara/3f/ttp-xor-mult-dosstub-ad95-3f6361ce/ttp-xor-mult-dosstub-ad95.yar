rule TTP_XOR_MULT_DOSStub_ad95 {
  strings:
    $key_ad95 = { f9 fd [2] 8d e5 [2] ca e7 [2] 8d f6 [2] c3 fa [2] cf f0 [2] d8 fb [2] c3 b5 [2] fe }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad92 {
  strings:
    $key_ad92 = { f9 fa [2] 8d e2 [2] ca e0 [2] 8d f1 [2] c3 fd [2] cf f7 [2] d8 fc [2] c3 b2 [2] fe }

  condition:
    any of them
}
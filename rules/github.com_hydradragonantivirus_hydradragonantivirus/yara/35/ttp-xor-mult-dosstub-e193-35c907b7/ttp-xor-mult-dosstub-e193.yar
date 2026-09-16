rule TTP_XOR_MULT_DOSStub_e193 {
  strings:
    $key_e193 = { b5 fb [2] c1 e3 [2] 86 e1 [2] c1 f0 [2] 8f fc [2] 83 f6 [2] 94 fd [2] 8f b3 [2] b2 }

  condition:
    any of them
}
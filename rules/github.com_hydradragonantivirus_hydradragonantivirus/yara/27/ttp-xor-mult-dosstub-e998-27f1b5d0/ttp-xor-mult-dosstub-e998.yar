rule TTP_XOR_MULT_DOSStub_e998 {
  strings:
    $key_e998 = { bd f0 [2] c9 e8 [2] 8e ea [2] c9 fb [2] 87 f7 [2] 8b fd [2] 9c f6 [2] 87 b8 [2] ba }

  condition:
    any of them
}
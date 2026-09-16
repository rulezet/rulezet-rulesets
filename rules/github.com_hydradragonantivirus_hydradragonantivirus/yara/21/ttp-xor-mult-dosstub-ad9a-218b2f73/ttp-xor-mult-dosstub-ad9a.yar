rule TTP_XOR_MULT_DOSStub_ad9a {
  strings:
    $key_ad9a = { f9 f2 [2] 8d ea [2] ca e8 [2] 8d f9 [2] c3 f5 [2] cf ff [2] d8 f4 [2] c3 ba [2] fe }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad9b {
  strings:
    $key_ad9b = { f9 f3 [2] 8d eb [2] ca e9 [2] 8d f8 [2] c3 f4 [2] cf fe [2] d8 f5 [2] c3 bb [2] fe }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad85 {
  strings:
    $key_ad85 = { f9 ed [2] 8d f5 [2] ca f7 [2] 8d e6 [2] c3 ea [2] cf e0 [2] d8 eb [2] c3 a5 [2] fe }

  condition:
    any of them
}
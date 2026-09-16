rule TTP_XOR_MULT_DOSStub_ad87 {
  strings:
    $key_ad87 = { f9 ef [2] 8d f7 [2] ca f5 [2] 8d e4 [2] c3 e8 [2] cf e2 [2] d8 e9 [2] c3 a7 [2] fe }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad8a {
  strings:
    $key_ad8a = { f9 e2 [2] 8d fa [2] ca f8 [2] 8d e9 [2] c3 e5 [2] cf ef [2] d8 e4 [2] c3 aa [2] fe }

  condition:
    any of them
}
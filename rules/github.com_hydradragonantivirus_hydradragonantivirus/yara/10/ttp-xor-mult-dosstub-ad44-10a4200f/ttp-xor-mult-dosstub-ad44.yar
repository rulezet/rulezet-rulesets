rule TTP_XOR_MULT_DOSStub_ad44 {
  strings:
    $key_ad44 = { f9 2c [2] 8d 34 [2] ca 36 [2] 8d 27 [2] c3 2b [2] cf 21 [2] d8 2a [2] c3 64 [2] fe }

  condition:
    any of them
}
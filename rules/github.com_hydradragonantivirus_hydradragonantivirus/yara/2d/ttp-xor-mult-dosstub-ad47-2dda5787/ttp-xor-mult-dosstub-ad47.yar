rule TTP_XOR_MULT_DOSStub_ad47 {
  strings:
    $key_ad47 = { f9 2f [2] 8d 37 [2] ca 35 [2] 8d 24 [2] c3 28 [2] cf 22 [2] d8 29 [2] c3 67 [2] fe }

  condition:
    any of them
}
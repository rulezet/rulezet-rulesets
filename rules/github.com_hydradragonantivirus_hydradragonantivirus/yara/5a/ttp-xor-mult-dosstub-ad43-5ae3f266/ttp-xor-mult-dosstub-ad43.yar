rule TTP_XOR_MULT_DOSStub_ad43 {
  strings:
    $key_ad43 = { f9 2b [2] 8d 33 [2] ca 31 [2] 8d 20 [2] c3 2c [2] cf 26 [2] d8 2d [2] c3 63 [2] fe }

  condition:
    any of them
}
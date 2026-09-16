rule TTP_XOR_MULT_DOSStub_ad49 {
  strings:
    $key_ad49 = { f9 21 [2] 8d 39 [2] ca 3b [2] 8d 2a [2] c3 26 [2] cf 2c [2] d8 27 [2] c3 69 [2] fe }

  condition:
    any of them
}
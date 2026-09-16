rule TTP_XOR_MULT_DOSStub_ad34 {
  strings:
    $key_ad34 = { f9 5c [2] 8d 44 [2] ca 46 [2] 8d 57 [2] c3 5b [2] cf 51 [2] d8 5a [2] c3 14 [2] fe }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad05 {
  strings:
    $key_ad05 = { f9 6d [2] 8d 75 [2] ca 77 [2] 8d 66 [2] c3 6a [2] cf 60 [2] d8 6b [2] c3 25 [2] fe }

  condition:
    any of them
}
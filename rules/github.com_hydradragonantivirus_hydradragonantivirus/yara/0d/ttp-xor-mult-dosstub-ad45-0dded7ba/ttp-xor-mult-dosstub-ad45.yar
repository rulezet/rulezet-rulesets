rule TTP_XOR_MULT_DOSStub_ad45 {
  strings:
    $key_ad45 = { f9 2d [2] 8d 35 [2] ca 37 [2] 8d 26 [2] c3 2a [2] cf 20 [2] d8 2b [2] c3 65 [2] fe }

  condition:
    any of them
}
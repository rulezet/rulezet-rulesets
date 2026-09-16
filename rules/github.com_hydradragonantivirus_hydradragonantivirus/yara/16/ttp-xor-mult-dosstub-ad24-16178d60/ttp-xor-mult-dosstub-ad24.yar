rule TTP_XOR_MULT_DOSStub_ad24 {
  strings:
    $key_ad24 = { f9 4c [2] 8d 54 [2] ca 56 [2] 8d 47 [2] c3 4b [2] cf 41 [2] d8 4a [2] c3 04 [2] fe }

  condition:
    any of them
}
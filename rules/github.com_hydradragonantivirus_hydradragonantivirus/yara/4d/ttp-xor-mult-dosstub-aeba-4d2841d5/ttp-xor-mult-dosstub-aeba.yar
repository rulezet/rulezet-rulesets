rule TTP_XOR_MULT_DOSStub_aeba {
  strings:
    $key_aeba = { fa d2 [2] 8e ca [2] c9 c8 [2] 8e d9 [2] c0 d5 [2] cc df [2] db d4 [2] c0 9a [2] fd }

  condition:
    any of them
}
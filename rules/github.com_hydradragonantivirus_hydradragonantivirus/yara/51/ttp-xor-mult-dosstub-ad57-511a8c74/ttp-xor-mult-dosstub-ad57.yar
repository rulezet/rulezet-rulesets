rule TTP_XOR_MULT_DOSStub_ad57 {
  strings:
    $key_ad57 = { f9 3f [2] 8d 27 [2] ca 25 [2] 8d 34 [2] c3 38 [2] cf 32 [2] d8 39 [2] c3 77 [2] fe }

  condition:
    any of them
}
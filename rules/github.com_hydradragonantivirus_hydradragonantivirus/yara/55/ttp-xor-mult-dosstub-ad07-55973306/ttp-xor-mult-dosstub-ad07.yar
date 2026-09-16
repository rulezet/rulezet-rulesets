rule TTP_XOR_MULT_DOSStub_ad07 {
  strings:
    $key_ad07 = { f9 6f [2] 8d 77 [2] ca 75 [2] 8d 64 [2] c3 68 [2] cf 62 [2] d8 69 [2] c3 27 [2] fe }

  condition:
    any of them
}
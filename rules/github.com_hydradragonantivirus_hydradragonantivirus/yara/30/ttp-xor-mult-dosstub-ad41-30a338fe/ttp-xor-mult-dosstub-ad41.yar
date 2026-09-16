rule TTP_XOR_MULT_DOSStub_ad41 {
  strings:
    $key_ad41 = { f9 29 [2] 8d 31 [2] ca 33 [2] 8d 22 [2] c3 2e [2] cf 24 [2] d8 2f [2] c3 61 [2] fe }

  condition:
    any of them
}
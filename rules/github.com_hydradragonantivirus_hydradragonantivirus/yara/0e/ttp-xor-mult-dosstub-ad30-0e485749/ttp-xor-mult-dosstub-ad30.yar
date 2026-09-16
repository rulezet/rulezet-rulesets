rule TTP_XOR_MULT_DOSStub_ad30 {
  strings:
    $key_ad30 = { f9 58 [2] 8d 40 [2] ca 42 [2] 8d 53 [2] c3 5f [2] cf 55 [2] d8 5e [2] c3 10 [2] fe }

  condition:
    any of them
}
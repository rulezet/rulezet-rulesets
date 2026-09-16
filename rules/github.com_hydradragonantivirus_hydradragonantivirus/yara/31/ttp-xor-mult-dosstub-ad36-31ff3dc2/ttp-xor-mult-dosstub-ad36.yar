rule TTP_XOR_MULT_DOSStub_ad36 {
  strings:
    $key_ad36 = { f9 5e [2] 8d 46 [2] ca 44 [2] 8d 55 [2] c3 59 [2] cf 53 [2] d8 58 [2] c3 16 [2] fe }

  condition:
    any of them
}
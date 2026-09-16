rule TTP_XOR_MULT_DOSStub_ad17 {
  strings:
    $key_ad17 = { f9 7f [2] 8d 67 [2] ca 65 [2] 8d 74 [2] c3 78 [2] cf 72 [2] d8 79 [2] c3 37 [2] fe }

  condition:
    any of them
}
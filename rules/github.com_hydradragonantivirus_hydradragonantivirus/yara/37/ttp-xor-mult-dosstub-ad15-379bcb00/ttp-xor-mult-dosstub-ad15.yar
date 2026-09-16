rule TTP_XOR_MULT_DOSStub_ad15 {
  strings:
    $key_ad15 = { f9 7d [2] 8d 65 [2] ca 67 [2] 8d 76 [2] c3 7a [2] cf 70 [2] d8 7b [2] c3 35 [2] fe }

  condition:
    any of them
}
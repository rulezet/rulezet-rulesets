rule TTP_XOR_MULT_DOSStub_ad63 {
  strings:
    $key_ad63 = { f9 0b [2] 8d 13 [2] ca 11 [2] 8d 00 [2] c3 0c [2] cf 06 [2] d8 0d [2] c3 43 [2] fe }

  condition:
    any of them
}
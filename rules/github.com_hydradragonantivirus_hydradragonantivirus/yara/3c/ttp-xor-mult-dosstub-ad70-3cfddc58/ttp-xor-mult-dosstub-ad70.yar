rule TTP_XOR_MULT_DOSStub_ad70 {
  strings:
    $key_ad70 = { f9 18 [2] 8d 00 [2] ca 02 [2] 8d 13 [2] c3 1f [2] cf 15 [2] d8 1e [2] c3 50 [2] fe }

  condition:
    any of them
}
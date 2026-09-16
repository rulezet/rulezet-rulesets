rule TTP_XOR_MULT_DOSStub_ad61 {
  strings:
    $key_ad61 = { f9 09 [2] 8d 11 [2] ca 13 [2] 8d 02 [2] c3 0e [2] cf 04 [2] d8 0f [2] c3 41 [2] fe }

  condition:
    any of them
}
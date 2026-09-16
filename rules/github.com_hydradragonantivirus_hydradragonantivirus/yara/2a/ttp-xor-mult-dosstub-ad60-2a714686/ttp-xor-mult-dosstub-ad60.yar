rule TTP_XOR_MULT_DOSStub_ad60 {
  strings:
    $key_ad60 = { f9 08 [2] 8d 10 [2] ca 12 [2] 8d 03 [2] c3 0f [2] cf 05 [2] d8 0e [2] c3 40 [2] fe }

  condition:
    any of them
}
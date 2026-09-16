rule TTP_XOR_MULT_DOSStub_ad67 {
  strings:
    $key_ad67 = { f9 0f [2] 8d 17 [2] ca 15 [2] 8d 04 [2] c3 08 [2] cf 02 [2] d8 09 [2] c3 47 [2] fe }

  condition:
    any of them
}
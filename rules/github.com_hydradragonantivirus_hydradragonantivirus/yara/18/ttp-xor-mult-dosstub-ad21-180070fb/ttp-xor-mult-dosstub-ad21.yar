rule TTP_XOR_MULT_DOSStub_ad21 {
  strings:
    $key_ad21 = { f9 49 [2] 8d 51 [2] ca 53 [2] 8d 42 [2] c3 4e [2] cf 44 [2] d8 4f [2] c3 01 [2] fe }

  condition:
    any of them
}
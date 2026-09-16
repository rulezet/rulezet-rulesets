rule TTP_XOR_MULT_DOSStub_ade7 {
  strings:
    $key_ade7 = { f9 8f [2] 8d 97 [2] ca 95 [2] 8d 84 [2] c3 88 [2] cf 82 [2] d8 89 [2] c3 c7 [2] fe }

  condition:
    any of them
}
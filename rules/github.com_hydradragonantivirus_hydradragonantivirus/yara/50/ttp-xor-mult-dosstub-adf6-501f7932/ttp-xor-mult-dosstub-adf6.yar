rule TTP_XOR_MULT_DOSStub_adf6 {
  strings:
    $key_adf6 = { f9 9e [2] 8d 86 [2] ca 84 [2] 8d 95 [2] c3 99 [2] cf 93 [2] d8 98 [2] c3 d6 [2] fe }

  condition:
    any of them
}
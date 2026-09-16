rule TTP_XOR_MULT_DOSStub_ad5c {
  strings:
    $key_ad5c = { f9 34 [2] 8d 2c [2] ca 2e [2] 8d 3f [2] c3 33 [2] cf 39 [2] d8 32 [2] c3 7c [2] fe }

  condition:
    any of them
}
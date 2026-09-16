rule TTP_XOR_MULT_DOSStub_ad7c {
  strings:
    $key_ad7c = { f9 14 [2] 8d 0c [2] ca 0e [2] 8d 1f [2] c3 13 [2] cf 19 [2] d8 12 [2] c3 5c [2] fe }

  condition:
    any of them
}
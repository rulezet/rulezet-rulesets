rule TTP_XOR_MULT_DOSStub_ad3a {
  strings:
    $key_ad3a = { f9 52 [2] 8d 4a [2] ca 48 [2] 8d 59 [2] c3 55 [2] cf 5f [2] d8 54 [2] c3 1a [2] fe }

  condition:
    any of them
}
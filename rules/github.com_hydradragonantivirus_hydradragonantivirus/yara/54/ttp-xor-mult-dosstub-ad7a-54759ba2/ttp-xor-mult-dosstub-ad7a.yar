rule TTP_XOR_MULT_DOSStub_ad7a {
  strings:
    $key_ad7a = { f9 12 [2] 8d 0a [2] ca 08 [2] 8d 19 [2] c3 15 [2] cf 1f [2] d8 14 [2] c3 5a [2] fe }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad7f {
  strings:
    $key_ad7f = { f9 17 [2] 8d 0f [2] ca 0d [2] 8d 1c [2] c3 10 [2] cf 1a [2] d8 11 [2] c3 5f [2] fe }

  condition:
    any of them
}
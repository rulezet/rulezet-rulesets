rule TTP_XOR_MULT_DOSStub_ad2d {
  strings:
    $key_ad2d = { f9 45 [2] 8d 5d [2] ca 5f [2] 8d 4e [2] c3 42 [2] cf 48 [2] d8 43 [2] c3 0d [2] fe }

  condition:
    any of them
}
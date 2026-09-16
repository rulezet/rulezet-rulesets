rule TTP_XOR_MULT_DOSStub_ad5d {
  strings:
    $key_ad5d = { f9 35 [2] 8d 2d [2] ca 2f [2] 8d 3e [2] c3 32 [2] cf 38 [2] d8 33 [2] c3 7d [2] fe }

  condition:
    any of them
}
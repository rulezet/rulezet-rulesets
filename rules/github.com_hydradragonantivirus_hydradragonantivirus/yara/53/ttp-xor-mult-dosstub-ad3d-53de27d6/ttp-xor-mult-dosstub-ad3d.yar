rule TTP_XOR_MULT_DOSStub_ad3d {
  strings:
    $key_ad3d = { f9 55 [2] 8d 4d [2] ca 4f [2] 8d 5e [2] c3 52 [2] cf 58 [2] d8 53 [2] c3 1d [2] fe }

  condition:
    any of them
}
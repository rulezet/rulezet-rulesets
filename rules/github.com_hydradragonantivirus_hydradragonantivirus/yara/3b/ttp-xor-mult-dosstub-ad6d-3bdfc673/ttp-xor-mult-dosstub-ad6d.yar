rule TTP_XOR_MULT_DOSStub_ad6d {
  strings:
    $key_ad6d = { f9 05 [2] 8d 1d [2] ca 1f [2] 8d 0e [2] c3 02 [2] cf 08 [2] d8 03 [2] c3 4d [2] fe }

  condition:
    any of them
}
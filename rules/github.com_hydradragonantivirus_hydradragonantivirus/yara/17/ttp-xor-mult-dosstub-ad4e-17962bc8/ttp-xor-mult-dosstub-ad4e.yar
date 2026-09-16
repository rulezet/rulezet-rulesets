rule TTP_XOR_MULT_DOSStub_ad4e {
  strings:
    $key_ad4e = { f9 26 [2] 8d 3e [2] ca 3c [2] 8d 2d [2] c3 21 [2] cf 2b [2] d8 20 [2] c3 6e [2] fe }

  condition:
    any of them
}
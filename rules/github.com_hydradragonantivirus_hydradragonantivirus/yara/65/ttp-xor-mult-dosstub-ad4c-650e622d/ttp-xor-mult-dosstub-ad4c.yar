rule TTP_XOR_MULT_DOSStub_ad4c {
  strings:
    $key_ad4c = { f9 24 [2] 8d 3c [2] ca 3e [2] 8d 2f [2] c3 23 [2] cf 29 [2] d8 22 [2] c3 6c [2] fe }

  condition:
    any of them
}
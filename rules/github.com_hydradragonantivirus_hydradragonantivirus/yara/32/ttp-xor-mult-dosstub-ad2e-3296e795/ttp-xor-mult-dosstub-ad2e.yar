rule TTP_XOR_MULT_DOSStub_ad2e {
  strings:
    $key_ad2e = { f9 46 [2] 8d 5e [2] ca 5c [2] 8d 4d [2] c3 41 [2] cf 4b [2] d8 40 [2] c3 0e [2] fe }

  condition:
    any of them
}
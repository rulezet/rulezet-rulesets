rule TTP_XOR_MULT_DOSStub_ad2b {
  strings:
    $key_ad2b = { f9 43 [2] 8d 5b [2] ca 59 [2] 8d 48 [2] c3 44 [2] cf 4e [2] d8 45 [2] c3 0b [2] fe }

  condition:
    any of them
}
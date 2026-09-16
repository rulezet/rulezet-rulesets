rule TTP_XOR_MULT_DOSStub_ad3b {
  strings:
    $key_ad3b = { f9 53 [2] 8d 4b [2] ca 49 [2] 8d 58 [2] c3 54 [2] cf 5e [2] d8 55 [2] c3 1b [2] fe }

  condition:
    any of them
}
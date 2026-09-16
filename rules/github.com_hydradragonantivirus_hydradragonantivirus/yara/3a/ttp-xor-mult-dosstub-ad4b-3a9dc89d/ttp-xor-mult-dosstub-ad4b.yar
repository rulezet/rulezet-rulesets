rule TTP_XOR_MULT_DOSStub_ad4b {
  strings:
    $key_ad4b = { f9 23 [2] 8d 3b [2] ca 39 [2] 8d 28 [2] c3 24 [2] cf 2e [2] d8 25 [2] c3 6b [2] fe }

  condition:
    any of them
}
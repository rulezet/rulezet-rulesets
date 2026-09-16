rule TTP_XOR_MULT_DOSStub_ad6b {
  strings:
    $key_ad6b = { f9 03 [2] 8d 1b [2] ca 19 [2] 8d 08 [2] c3 04 [2] cf 0e [2] d8 05 [2] c3 4b [2] fe }

  condition:
    any of them
}
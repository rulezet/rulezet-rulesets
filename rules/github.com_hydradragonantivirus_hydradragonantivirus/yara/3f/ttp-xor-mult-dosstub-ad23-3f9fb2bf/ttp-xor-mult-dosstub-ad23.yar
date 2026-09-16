rule TTP_XOR_MULT_DOSStub_ad23 {
  strings:
    $key_ad23 = { f9 4b [2] 8d 53 [2] ca 51 [2] 8d 40 [2] c3 4c [2] cf 46 [2] d8 4d [2] c3 03 [2] fe }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ad12 {
  strings:
    $key_ad12 = { f9 7a [2] 8d 62 [2] ca 60 [2] 8d 71 [2] c3 7d [2] cf 77 [2] d8 7c [2] c3 32 [2] fe }

  condition:
    any of them
}
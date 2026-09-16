rule TTP_XOR_MULT_DOSStub_ade5 {
  strings:
    $key_ade5 = { f9 8d [2] 8d 95 [2] ca 97 [2] 8d 86 [2] c3 8a [2] cf 80 [2] d8 8b [2] c3 c5 [2] fe }

  condition:
    any of them
}
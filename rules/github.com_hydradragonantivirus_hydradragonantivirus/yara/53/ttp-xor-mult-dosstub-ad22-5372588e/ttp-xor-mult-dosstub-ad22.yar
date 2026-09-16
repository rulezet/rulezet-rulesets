rule TTP_XOR_MULT_DOSStub_ad22 {
  strings:
    $key_ad22 = { f9 4a [2] 8d 52 [2] ca 50 [2] 8d 41 [2] c3 4d [2] cf 47 [2] d8 4c [2] c3 02 [2] fe }

  condition:
    any of them
}
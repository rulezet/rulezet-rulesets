rule TTP_XOR_MULT_DOSStub_adf2 {
  strings:
    $key_adf2 = { f9 9a [2] 8d 82 [2] ca 80 [2] 8d 91 [2] c3 9d [2] cf 97 [2] d8 9c [2] c3 d2 [2] fe }

  condition:
    any of them
}
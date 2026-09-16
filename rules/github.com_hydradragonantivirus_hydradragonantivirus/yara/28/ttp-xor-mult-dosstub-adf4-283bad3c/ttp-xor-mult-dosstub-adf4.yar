rule TTP_XOR_MULT_DOSStub_adf4 {
  strings:
    $key_adf4 = { f9 9c [2] 8d 84 [2] ca 86 [2] 8d 97 [2] c3 9b [2] cf 91 [2] d8 9a [2] c3 d4 [2] fe }

  condition:
    any of them
}
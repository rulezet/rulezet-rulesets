rule TTP_XOR_MULT_DOSStub_adf8 {
  strings:
    $key_adf8 = { f9 90 [2] 8d 88 [2] ca 8a [2] 8d 9b [2] c3 97 [2] cf 9d [2] d8 96 [2] c3 d8 [2] fe }

  condition:
    any of them
}
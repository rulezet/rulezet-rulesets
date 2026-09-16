rule TTP_XOR_MULT_DOSStub_ade6 {
  strings:
    $key_ade6 = { f9 8e [2] 8d 96 [2] ca 94 [2] 8d 85 [2] c3 89 [2] cf 83 [2] d8 88 [2] c3 c6 [2] fe }

  condition:
    any of them
}
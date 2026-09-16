rule TTP_XOR_MULT_DOSStub_adfc {
  strings:
    $key_adfc = { f9 94 [2] 8d 8c [2] ca 8e [2] 8d 9f [2] c3 93 [2] cf 99 [2] d8 92 [2] c3 dc [2] fe }

  condition:
    any of them
}
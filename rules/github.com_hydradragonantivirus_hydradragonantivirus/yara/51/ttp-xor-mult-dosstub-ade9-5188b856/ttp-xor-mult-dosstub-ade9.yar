rule TTP_XOR_MULT_DOSStub_ade9 {
  strings:
    $key_ade9 = { f9 81 [2] 8d 99 [2] ca 9b [2] 8d 8a [2] c3 86 [2] cf 8c [2] d8 87 [2] c3 c9 [2] fe }

  condition:
    any of them
}
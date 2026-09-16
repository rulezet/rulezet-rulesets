rule TTP_XOR_MULT_DOSStub_e99b {
  strings:
    $key_e99b = { bd f3 [2] c9 eb [2] 8e e9 [2] c9 f8 [2] 87 f4 [2] 8b fe [2] 9c f5 [2] 87 bb [2] ba }

  condition:
    any of them
}
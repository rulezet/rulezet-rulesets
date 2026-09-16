rule TTP_XOR_MULT_DOSStub_aea9 {
  strings:
    $key_aea9 = { fa c1 [2] 8e d9 [2] c9 db [2] 8e ca [2] c0 c6 [2] cc cc [2] db c7 [2] c0 89 [2] fd }

  condition:
    any of them
}
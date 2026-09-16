rule TTP_XOR_MULT_DOSStub_fba9 {
  strings:
    $key_fba9 = { af c1 [2] db d9 [2] 9c db [2] db ca [2] 95 c6 [2] 99 cc [2] 8e c7 [2] 95 89 [2] a8 }

  condition:
    any of them
}
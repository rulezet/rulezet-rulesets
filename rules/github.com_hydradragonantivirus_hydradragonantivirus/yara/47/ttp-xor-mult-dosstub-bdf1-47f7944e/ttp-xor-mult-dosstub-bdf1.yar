rule TTP_XOR_MULT_DOSStub_bdf1 {
  strings:
    $key_bdf1 = { e9 99 [2] 9d 81 [2] da 83 [2] 9d 92 [2] d3 9e [2] df 94 [2] c8 9f [2] d3 d1 [2] ee }

  condition:
    any of them
}
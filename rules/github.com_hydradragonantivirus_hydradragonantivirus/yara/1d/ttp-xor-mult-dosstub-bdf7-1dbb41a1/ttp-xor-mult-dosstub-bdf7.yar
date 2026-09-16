rule TTP_XOR_MULT_DOSStub_bdf7 {
  strings:
    $key_bdf7 = { e9 9f [2] 9d 87 [2] da 85 [2] 9d 94 [2] d3 98 [2] df 92 [2] c8 99 [2] d3 d7 [2] ee }

  condition:
    any of them
}
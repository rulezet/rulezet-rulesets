rule TTP_XOR_MULT_DOSStub_bde6 {
  strings:
    $key_bde6 = { e9 8e [2] 9d 96 [2] da 94 [2] 9d 85 [2] d3 89 [2] df 83 [2] c8 88 [2] d3 c6 [2] ee }

  condition:
    any of them
}
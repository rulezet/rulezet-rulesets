rule TTP_XOR_MULT_DOSStub_bde4 {
  strings:
    $key_bde4 = { e9 8c [2] 9d 94 [2] da 96 [2] 9d 87 [2] d3 8b [2] df 81 [2] c8 8a [2] d3 c4 [2] ee }

  condition:
    any of them
}
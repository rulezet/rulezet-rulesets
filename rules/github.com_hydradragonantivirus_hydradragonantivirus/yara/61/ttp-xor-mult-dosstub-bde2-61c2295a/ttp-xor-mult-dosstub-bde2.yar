rule TTP_XOR_MULT_DOSStub_bde2 {
  strings:
    $key_bde2 = { e9 8a [2] 9d 92 [2] da 90 [2] 9d 81 [2] d3 8d [2] df 87 [2] c8 8c [2] d3 c2 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bde9 {
  strings:
    $key_bde9 = { e9 81 [2] 9d 99 [2] da 9b [2] 9d 8a [2] d3 86 [2] df 8c [2] c8 87 [2] d3 c9 [2] ee }

  condition:
    any of them
}
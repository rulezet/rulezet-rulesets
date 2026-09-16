rule TTP_XOR_MULT_DOSStub_bd18 {
  strings:
    $key_bd18 = { e9 70 [2] 9d 68 [2] da 6a [2] 9d 7b [2] d3 77 [2] df 7d [2] c8 76 [2] d3 38 [2] ee }

  condition:
    any of them
}
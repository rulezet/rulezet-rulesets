rule TTP_XOR_MULT_DOSStub_bd34 {
  strings:
    $key_bd34 = { e9 5c [2] 9d 44 [2] da 46 [2] 9d 57 [2] d3 5b [2] df 51 [2] c8 5a [2] d3 14 [2] ee }

  condition:
    any of them
}
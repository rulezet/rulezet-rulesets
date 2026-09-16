rule TTP_XOR_MULT_DOSStub_bd25 {
  strings:
    $key_bd25 = { e9 4d [2] 9d 55 [2] da 57 [2] 9d 46 [2] d3 4a [2] df 40 [2] c8 4b [2] d3 05 [2] ee }

  condition:
    any of them
}
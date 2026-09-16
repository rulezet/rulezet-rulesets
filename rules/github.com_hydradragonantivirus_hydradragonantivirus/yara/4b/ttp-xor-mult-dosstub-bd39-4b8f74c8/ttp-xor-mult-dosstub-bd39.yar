rule TTP_XOR_MULT_DOSStub_bd39 {
  strings:
    $key_bd39 = { e9 51 [2] 9d 49 [2] da 4b [2] 9d 5a [2] d3 56 [2] df 5c [2] c8 57 [2] d3 19 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd59 {
  strings:
    $key_bd59 = { e9 31 [2] 9d 29 [2] da 2b [2] 9d 3a [2] d3 36 [2] df 3c [2] c8 37 [2] d3 79 [2] ee }

  condition:
    any of them
}
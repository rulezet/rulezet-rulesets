rule TTP_XOR_MULT_DOSStub_bd75 {
  strings:
    $key_bd75 = { e9 1d [2] 9d 05 [2] da 07 [2] 9d 16 [2] d3 1a [2] df 10 [2] c8 1b [2] d3 55 [2] ee }

  condition:
    any of them
}
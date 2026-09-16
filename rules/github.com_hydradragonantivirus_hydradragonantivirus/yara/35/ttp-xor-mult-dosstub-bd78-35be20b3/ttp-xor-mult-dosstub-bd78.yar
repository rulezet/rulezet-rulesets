rule TTP_XOR_MULT_DOSStub_bd78 {
  strings:
    $key_bd78 = { e9 10 [2] 9d 08 [2] da 0a [2] 9d 1b [2] d3 17 [2] df 1d [2] c8 16 [2] d3 58 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd48 {
  strings:
    $key_bd48 = { e9 20 [2] 9d 38 [2] da 3a [2] 9d 2b [2] d3 27 [2] df 2d [2] c8 26 [2] d3 68 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd65 {
  strings:
    $key_bd65 = { e9 0d [2] 9d 15 [2] da 17 [2] 9d 06 [2] d3 0a [2] df 00 [2] c8 0b [2] d3 45 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd26 {
  strings:
    $key_bd26 = { e9 4e [2] 9d 56 [2] da 54 [2] 9d 45 [2] d3 49 [2] df 43 [2] c8 48 [2] d3 06 [2] ee }

  condition:
    any of them
}
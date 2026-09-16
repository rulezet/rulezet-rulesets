rule TTP_XOR_MULT_DOSStub_bd51 {
  strings:
    $key_bd51 = { e9 39 [2] 9d 21 [2] da 23 [2] 9d 32 [2] d3 3e [2] df 34 [2] c8 3f [2] d3 71 [2] ee }

  condition:
    any of them
}
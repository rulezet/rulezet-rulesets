rule TTP_XOR_MULT_DOSStub_bd56 {
  strings:
    $key_bd56 = { e9 3e [2] 9d 26 [2] da 24 [2] 9d 35 [2] d3 39 [2] df 33 [2] c8 38 [2] d3 76 [2] ee }

  condition:
    any of them
}
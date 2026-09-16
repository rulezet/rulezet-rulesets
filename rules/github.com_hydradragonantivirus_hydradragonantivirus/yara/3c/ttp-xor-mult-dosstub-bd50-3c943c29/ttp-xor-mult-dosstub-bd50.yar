rule TTP_XOR_MULT_DOSStub_bd50 {
  strings:
    $key_bd50 = { e9 38 [2] 9d 20 [2] da 22 [2] 9d 33 [2] d3 3f [2] df 35 [2] c8 3e [2] d3 70 [2] ee }

  condition:
    any of them
}
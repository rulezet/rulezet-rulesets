rule TTP_XOR_MULT_DOSStub_bd30 {
  strings:
    $key_bd30 = { e9 58 [2] 9d 40 [2] da 42 [2] 9d 53 [2] d3 5f [2] df 55 [2] c8 5e [2] d3 10 [2] ee }

  condition:
    any of them
}
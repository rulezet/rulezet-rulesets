rule TTP_XOR_MULT_DOSStub_bd40 {
  strings:
    $key_bd40 = { e9 28 [2] 9d 30 [2] da 32 [2] 9d 23 [2] d3 2f [2] df 25 [2] c8 2e [2] d3 60 [2] ee }

  condition:
    any of them
}
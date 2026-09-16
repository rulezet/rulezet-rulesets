rule TTP_XOR_MULT_DOSStub_bd60 {
  strings:
    $key_bd60 = { e9 08 [2] 9d 10 [2] da 12 [2] 9d 03 [2] d3 0f [2] df 05 [2] c8 0e [2] d3 40 [2] ee }

  condition:
    any of them
}
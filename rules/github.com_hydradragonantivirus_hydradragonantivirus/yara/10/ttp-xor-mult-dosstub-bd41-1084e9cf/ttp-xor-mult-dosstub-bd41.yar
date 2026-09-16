rule TTP_XOR_MULT_DOSStub_bd41 {
  strings:
    $key_bd41 = { e9 29 [2] 9d 31 [2] da 33 [2] 9d 22 [2] d3 2e [2] df 24 [2] c8 2f [2] d3 61 [2] ee }

  condition:
    any of them
}
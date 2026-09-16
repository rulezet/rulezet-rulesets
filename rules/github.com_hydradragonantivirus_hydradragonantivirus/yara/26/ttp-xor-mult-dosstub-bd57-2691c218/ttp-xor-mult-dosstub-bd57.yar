rule TTP_XOR_MULT_DOSStub_bd57 {
  strings:
    $key_bd57 = { e9 3f [2] 9d 27 [2] da 25 [2] 9d 34 [2] d3 38 [2] df 32 [2] c8 39 [2] d3 77 [2] ee }

  condition:
    any of them
}
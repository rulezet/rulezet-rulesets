rule TTP_XOR_MULT_DOSStub_bd17 {
  strings:
    $key_bd17 = { e9 7f [2] 9d 67 [2] da 65 [2] 9d 74 [2] d3 78 [2] df 72 [2] c8 79 [2] d3 37 [2] ee }

  condition:
    any of them
}
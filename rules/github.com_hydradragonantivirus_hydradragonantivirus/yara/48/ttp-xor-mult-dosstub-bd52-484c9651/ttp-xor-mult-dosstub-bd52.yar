rule TTP_XOR_MULT_DOSStub_bd52 {
  strings:
    $key_bd52 = { e9 3a [2] 9d 22 [2] da 20 [2] 9d 31 [2] d3 3d [2] df 37 [2] c8 3c [2] d3 72 [2] ee }

  condition:
    any of them
}
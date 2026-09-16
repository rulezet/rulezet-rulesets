rule TTP_XOR_MULT_DOSStub_bd5d {
  strings:
    $key_bd5d = { e9 35 [2] 9d 2d [2] da 2f [2] 9d 3e [2] d3 32 [2] df 38 [2] c8 33 [2] d3 7d [2] ee }

  condition:
    any of them
}
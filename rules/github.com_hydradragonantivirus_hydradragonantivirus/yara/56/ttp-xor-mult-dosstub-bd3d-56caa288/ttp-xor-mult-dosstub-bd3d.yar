rule TTP_XOR_MULT_DOSStub_bd3d {
  strings:
    $key_bd3d = { e9 55 [2] 9d 4d [2] da 4f [2] 9d 5e [2] d3 52 [2] df 58 [2] c8 53 [2] d3 1d [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd1d {
  strings:
    $key_bd1d = { e9 75 [2] 9d 6d [2] da 6f [2] 9d 7e [2] d3 72 [2] df 78 [2] c8 73 [2] d3 3d [2] ee }

  condition:
    any of them
}
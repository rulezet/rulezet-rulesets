rule TTP_XOR_MULT_DOSStub_bd4d {
  strings:
    $key_bd4d = { e9 25 [2] 9d 3d [2] da 3f [2] 9d 2e [2] d3 22 [2] df 28 [2] c8 23 [2] d3 6d [2] ee }

  condition:
    any of them
}
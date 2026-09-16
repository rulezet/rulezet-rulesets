rule TTP_XOR_MULT_DOSStub_bd5f {
  strings:
    $key_bd5f = { e9 37 [2] 9d 2f [2] da 2d [2] 9d 3c [2] d3 30 [2] df 3a [2] c8 31 [2] d3 7f [2] ee }

  condition:
    any of them
}
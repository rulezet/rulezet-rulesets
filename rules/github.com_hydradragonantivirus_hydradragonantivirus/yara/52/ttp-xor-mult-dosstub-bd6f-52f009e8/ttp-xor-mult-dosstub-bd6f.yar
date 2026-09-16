rule TTP_XOR_MULT_DOSStub_bd6f {
  strings:
    $key_bd6f = { e9 07 [2] 9d 1f [2] da 1d [2] 9d 0c [2] d3 00 [2] df 0a [2] c8 01 [2] d3 4f [2] ee }

  condition:
    any of them
}
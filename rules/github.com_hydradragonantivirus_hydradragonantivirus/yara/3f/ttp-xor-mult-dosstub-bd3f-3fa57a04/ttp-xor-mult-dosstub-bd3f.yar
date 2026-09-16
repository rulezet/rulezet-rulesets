rule TTP_XOR_MULT_DOSStub_bd3f {
  strings:
    $key_bd3f = { e9 57 [2] 9d 4f [2] da 4d [2] 9d 5c [2] d3 50 [2] df 5a [2] c8 51 [2] d3 1f [2] ee }

  condition:
    any of them
}
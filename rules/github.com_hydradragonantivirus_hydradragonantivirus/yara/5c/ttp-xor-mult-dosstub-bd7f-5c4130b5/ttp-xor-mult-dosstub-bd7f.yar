rule TTP_XOR_MULT_DOSStub_bd7f {
  strings:
    $key_bd7f = { e9 17 [2] 9d 0f [2] da 0d [2] 9d 1c [2] d3 10 [2] df 1a [2] c8 11 [2] d3 5f [2] ee }

  condition:
    any of them
}
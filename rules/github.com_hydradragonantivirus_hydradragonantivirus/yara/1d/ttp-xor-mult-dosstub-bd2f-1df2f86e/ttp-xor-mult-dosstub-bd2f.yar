rule TTP_XOR_MULT_DOSStub_bd2f {
  strings:
    $key_bd2f = { e9 47 [2] 9d 5f [2] da 5d [2] 9d 4c [2] d3 40 [2] df 4a [2] c8 41 [2] d3 0f [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd1f {
  strings:
    $key_bd1f = { e9 77 [2] 9d 6f [2] da 6d [2] 9d 7c [2] d3 70 [2] df 7a [2] c8 71 [2] d3 3f [2] ee }

  condition:
    any of them
}
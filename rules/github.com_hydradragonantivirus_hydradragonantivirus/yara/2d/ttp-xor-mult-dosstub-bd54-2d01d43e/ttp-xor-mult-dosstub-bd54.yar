rule TTP_XOR_MULT_DOSStub_bd54 {
  strings:
    $key_bd54 = { e9 3c [2] 9d 24 [2] da 26 [2] 9d 37 [2] d3 3b [2] df 31 [2] c8 3a [2] d3 74 [2] ee }

  condition:
    any of them
}
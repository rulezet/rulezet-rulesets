rule TTP_XOR_MULT_DOSStub_bd04 {
  strings:
    $key_bd04 = { e9 6c [2] 9d 74 [2] da 76 [2] 9d 67 [2] d3 6b [2] df 61 [2] c8 6a [2] d3 24 [2] ee }

  condition:
    any of them
}
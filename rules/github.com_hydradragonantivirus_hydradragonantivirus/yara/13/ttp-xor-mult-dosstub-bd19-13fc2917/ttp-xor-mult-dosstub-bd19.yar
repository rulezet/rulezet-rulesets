rule TTP_XOR_MULT_DOSStub_bd19 {
  strings:
    $key_bd19 = { e9 71 [2] 9d 69 [2] da 6b [2] 9d 7a [2] d3 76 [2] df 7c [2] c8 77 [2] d3 39 [2] ee }

  condition:
    any of them
}
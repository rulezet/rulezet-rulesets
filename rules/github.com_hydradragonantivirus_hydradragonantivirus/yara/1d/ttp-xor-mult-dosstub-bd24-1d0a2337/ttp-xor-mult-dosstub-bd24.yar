rule TTP_XOR_MULT_DOSStub_bd24 {
  strings:
    $key_bd24 = { e9 4c [2] 9d 54 [2] da 56 [2] 9d 47 [2] d3 4b [2] df 41 [2] c8 4a [2] d3 04 [2] ee }

  condition:
    any of them
}
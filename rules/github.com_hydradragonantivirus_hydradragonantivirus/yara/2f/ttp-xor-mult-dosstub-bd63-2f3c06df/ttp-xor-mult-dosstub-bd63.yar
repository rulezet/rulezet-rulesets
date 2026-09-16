rule TTP_XOR_MULT_DOSStub_bd63 {
  strings:
    $key_bd63 = { e9 0b [2] 9d 13 [2] da 11 [2] 9d 00 [2] d3 0c [2] df 06 [2] c8 0d [2] d3 43 [2] ee }

  condition:
    any of them
}
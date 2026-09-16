rule TTP_XOR_MULT_DOSStub_bd64 {
  strings:
    $key_bd64 = { e9 0c [2] 9d 14 [2] da 16 [2] 9d 07 [2] d3 0b [2] df 01 [2] c8 0a [2] d3 44 [2] ee }

  condition:
    any of them
}
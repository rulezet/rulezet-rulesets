rule TTP_XOR_MULT_DOSStub_bd69 {
  strings:
    $key_bd69 = { e9 01 [2] 9d 19 [2] da 1b [2] 9d 0a [2] d3 06 [2] df 0c [2] c8 07 [2] d3 49 [2] ee }

  condition:
    any of them
}
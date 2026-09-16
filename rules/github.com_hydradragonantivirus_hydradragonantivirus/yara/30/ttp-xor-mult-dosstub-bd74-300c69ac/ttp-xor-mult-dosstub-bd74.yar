rule TTP_XOR_MULT_DOSStub_bd74 {
  strings:
    $key_bd74 = { e9 1c [2] 9d 04 [2] da 06 [2] 9d 17 [2] d3 1b [2] df 11 [2] c8 1a [2] d3 54 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd28 {
  strings:
    $key_bd28 = { e9 40 [2] 9d 58 [2] da 5a [2] 9d 4b [2] d3 47 [2] df 4d [2] c8 46 [2] d3 08 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bdf8 {
  strings:
    $key_bdf8 = { e9 90 [2] 9d 88 [2] da 8a [2] 9d 9b [2] d3 97 [2] df 9d [2] c8 96 [2] d3 d8 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bdf9 {
  strings:
    $key_bdf9 = { e9 91 [2] 9d 89 [2] da 8b [2] 9d 9a [2] d3 96 [2] df 9c [2] c8 97 [2] d3 d9 [2] ee }

  condition:
    any of them
}
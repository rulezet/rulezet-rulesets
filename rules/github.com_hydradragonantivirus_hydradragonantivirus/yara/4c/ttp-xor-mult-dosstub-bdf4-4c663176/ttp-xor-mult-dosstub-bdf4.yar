rule TTP_XOR_MULT_DOSStub_bdf4 {
  strings:
    $key_bdf4 = { e9 9c [2] 9d 84 [2] da 86 [2] 9d 97 [2] d3 9b [2] df 91 [2] c8 9a [2] d3 d4 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd05 {
  strings:
    $key_bd05 = { e9 6d [2] 9d 75 [2] da 77 [2] 9d 66 [2] d3 6a [2] df 60 [2] c8 6b [2] d3 25 [2] ee }

  condition:
    any of them
}
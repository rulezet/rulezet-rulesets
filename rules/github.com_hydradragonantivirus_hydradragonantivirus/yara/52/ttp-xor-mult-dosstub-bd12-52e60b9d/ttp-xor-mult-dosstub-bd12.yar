rule TTP_XOR_MULT_DOSStub_bd12 {
  strings:
    $key_bd12 = { e9 7a [2] 9d 62 [2] da 60 [2] 9d 71 [2] d3 7d [2] df 77 [2] c8 7c [2] d3 32 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bde8 {
  strings:
    $key_bde8 = { e9 80 [2] 9d 98 [2] da 9a [2] 9d 8b [2] d3 87 [2] df 8d [2] c8 86 [2] d3 c8 [2] ee }

  condition:
    any of them
}
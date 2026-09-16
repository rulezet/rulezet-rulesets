rule TTP_XOR_MULT_DOSStub_bde5 {
  strings:
    $key_bde5 = { e9 8d [2] 9d 95 [2] da 97 [2] 9d 86 [2] d3 8a [2] df 80 [2] c8 8b [2] d3 c5 [2] ee }

  condition:
    any of them
}
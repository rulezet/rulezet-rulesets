rule TTP_XOR_MULT_DOSStub_bdeb {
  strings:
    $key_bdeb = { e9 83 [2] 9d 9b [2] da 99 [2] 9d 88 [2] d3 84 [2] df 8e [2] c8 85 [2] d3 cb [2] ee }

  condition:
    any of them
}
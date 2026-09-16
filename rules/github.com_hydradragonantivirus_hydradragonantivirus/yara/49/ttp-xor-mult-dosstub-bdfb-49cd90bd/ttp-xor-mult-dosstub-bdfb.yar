rule TTP_XOR_MULT_DOSStub_bdfb {
  strings:
    $key_bdfb = { e9 93 [2] 9d 8b [2] da 89 [2] 9d 98 [2] d3 94 [2] df 9e [2] c8 95 [2] d3 db [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bd2e {
  strings:
    $key_bd2e = { e9 46 [2] 9d 5e [2] da 5c [2] 9d 4d [2] d3 41 [2] df 4b [2] c8 40 [2] d3 0e [2] ee }

  condition:
    any of them
}
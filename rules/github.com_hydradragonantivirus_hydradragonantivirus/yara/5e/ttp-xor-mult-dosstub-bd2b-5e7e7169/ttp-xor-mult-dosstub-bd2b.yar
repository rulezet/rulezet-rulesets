rule TTP_XOR_MULT_DOSStub_bd2b {
  strings:
    $key_bd2b = { e9 43 [2] 9d 5b [2] da 59 [2] 9d 48 [2] d3 44 [2] df 4e [2] c8 45 [2] d3 0b [2] ee }

  condition:
    any of them
}
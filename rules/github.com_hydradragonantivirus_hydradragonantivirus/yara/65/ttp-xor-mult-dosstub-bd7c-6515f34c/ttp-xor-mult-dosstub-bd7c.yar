rule TTP_XOR_MULT_DOSStub_bd7c {
  strings:
    $key_bd7c = { e9 14 [2] 9d 0c [2] da 0e [2] 9d 1f [2] d3 13 [2] df 19 [2] c8 12 [2] d3 5c [2] ee }

  condition:
    any of them
}
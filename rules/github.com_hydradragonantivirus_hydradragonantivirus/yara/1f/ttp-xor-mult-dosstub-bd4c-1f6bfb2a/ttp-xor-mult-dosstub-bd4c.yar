rule TTP_XOR_MULT_DOSStub_bd4c {
  strings:
    $key_bd4c = { e9 24 [2] 9d 3c [2] da 3e [2] 9d 2f [2] d3 23 [2] df 29 [2] c8 22 [2] d3 6c [2] ee }

  condition:
    any of them
}
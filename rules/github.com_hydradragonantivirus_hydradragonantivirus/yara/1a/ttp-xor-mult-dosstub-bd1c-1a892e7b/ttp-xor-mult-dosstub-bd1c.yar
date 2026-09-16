rule TTP_XOR_MULT_DOSStub_bd1c {
  strings:
    $key_bd1c = { e9 74 [2] 9d 6c [2] da 6e [2] 9d 7f [2] d3 73 [2] df 79 [2] c8 72 [2] d3 3c [2] ee }

  condition:
    any of them
}
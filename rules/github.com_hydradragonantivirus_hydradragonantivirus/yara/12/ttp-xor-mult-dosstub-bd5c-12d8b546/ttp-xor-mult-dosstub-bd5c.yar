rule TTP_XOR_MULT_DOSStub_bd5c {
  strings:
    $key_bd5c = { e9 34 [2] 9d 2c [2] da 2e [2] 9d 3f [2] d3 33 [2] df 39 [2] c8 32 [2] d3 7c [2] ee }

  condition:
    any of them
}
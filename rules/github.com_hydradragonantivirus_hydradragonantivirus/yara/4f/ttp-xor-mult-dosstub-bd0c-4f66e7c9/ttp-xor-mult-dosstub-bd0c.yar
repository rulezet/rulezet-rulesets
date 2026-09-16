rule TTP_XOR_MULT_DOSStub_bd0c {
  strings:
    $key_bd0c = { e9 64 [2] 9d 7c [2] da 7e [2] 9d 6f [2] d3 63 [2] df 69 [2] c8 62 [2] d3 2c [2] ee }

  condition:
    any of them
}
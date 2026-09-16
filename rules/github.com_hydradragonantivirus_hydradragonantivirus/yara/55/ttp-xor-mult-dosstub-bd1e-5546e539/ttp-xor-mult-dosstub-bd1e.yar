rule TTP_XOR_MULT_DOSStub_bd1e {
  strings:
    $key_bd1e = { e9 76 [2] 9d 6e [2] da 6c [2] 9d 7d [2] d3 71 [2] df 7b [2] c8 70 [2] d3 3e [2] ee }

  condition:
    any of them
}
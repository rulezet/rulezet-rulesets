rule TTP_XOR_MULT_DOSStub_bde1 {
  strings:
    $key_bde1 = { e9 89 [2] 9d 91 [2] da 93 [2] 9d 82 [2] d3 8e [2] df 84 [2] c8 8f [2] d3 c1 [2] ee }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_bde7 {
  strings:
    $key_bde7 = { e9 8f [2] 9d 97 [2] da 95 [2] 9d 84 [2] d3 88 [2] df 82 [2] c8 89 [2] d3 c7 [2] ee }

  condition:
    any of them
}
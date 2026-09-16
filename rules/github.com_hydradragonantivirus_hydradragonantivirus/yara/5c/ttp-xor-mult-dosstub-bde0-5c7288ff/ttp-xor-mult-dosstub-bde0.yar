rule TTP_XOR_MULT_DOSStub_bde0 {
  strings:
    $key_bde0 = { e9 88 [2] 9d 90 [2] da 92 [2] 9d 83 [2] d3 8f [2] df 85 [2] c8 8e [2] d3 c0 [2] ee }

  condition:
    any of them
}
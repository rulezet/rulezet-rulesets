rule TTP_XOR_MULT_DOSStub_bd37 {
  strings:
    $key_bd37 = { e9 5f [2] 9d 47 [2] da 45 [2] 9d 54 [2] d3 58 [2] df 52 [2] c8 59 [2] d3 17 [2] ee }

  condition:
    any of them
}
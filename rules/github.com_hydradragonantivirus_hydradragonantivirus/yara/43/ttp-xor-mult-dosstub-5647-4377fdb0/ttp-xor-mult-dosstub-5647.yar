rule TTP_XOR_MULT_DOSStub_5647 {
  strings:
    $key_5647 = { 02 2f [2] 76 37 [2] 31 35 [2] 76 24 [2] 38 28 [2] 34 22 [2] 23 29 [2] 38 67 [2] 05 }

  condition:
    any of them
}
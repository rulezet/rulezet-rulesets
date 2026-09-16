rule TTP_XOR_MULT_DOSStub_6647 {
  strings:
    $key_6647 = { 32 2f [2] 46 37 [2] 01 35 [2] 46 24 [2] 08 28 [2] 04 22 [2] 13 29 [2] 08 67 [2] 35 }

  condition:
    any of them
}
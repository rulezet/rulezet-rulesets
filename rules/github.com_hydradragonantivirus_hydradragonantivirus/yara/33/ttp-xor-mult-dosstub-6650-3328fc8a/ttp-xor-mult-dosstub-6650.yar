rule TTP_XOR_MULT_DOSStub_6650 {
  strings:
    $key_6650 = { 32 38 [2] 46 20 [2] 01 22 [2] 46 33 [2] 08 3f [2] 04 35 [2] 13 3e [2] 08 70 [2] 35 }

  condition:
    any of them
}
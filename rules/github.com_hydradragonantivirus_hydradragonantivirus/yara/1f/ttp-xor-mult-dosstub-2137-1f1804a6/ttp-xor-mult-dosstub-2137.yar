rule TTP_XOR_MULT_DOSStub_2137 {
  strings:
    $key_2137 = { 75 5f [2] 01 47 [2] 46 45 [2] 01 54 [2] 4f 58 [2] 43 52 [2] 54 59 [2] 4f 17 [2] 72 }

  condition:
    any of them
}
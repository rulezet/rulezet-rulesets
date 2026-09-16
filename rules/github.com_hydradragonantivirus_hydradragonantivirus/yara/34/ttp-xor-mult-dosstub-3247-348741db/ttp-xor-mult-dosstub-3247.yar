rule TTP_XOR_MULT_DOSStub_3247 {
  strings:
    $key_3247 = { 66 2f [2] 12 37 [2] 55 35 [2] 12 24 [2] 5c 28 [2] 50 22 [2] 47 29 [2] 5c 67 [2] 61 }

  condition:
    any of them
}
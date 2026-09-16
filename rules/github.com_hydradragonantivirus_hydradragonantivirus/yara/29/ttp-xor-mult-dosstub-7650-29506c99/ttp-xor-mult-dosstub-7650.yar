rule TTP_XOR_MULT_DOSStub_7650 {
  strings:
    $key_7650 = { 22 38 [2] 56 20 [2] 11 22 [2] 56 33 [2] 18 3f [2] 14 35 [2] 03 3e [2] 18 70 [2] 25 }

  condition:
    any of them
}
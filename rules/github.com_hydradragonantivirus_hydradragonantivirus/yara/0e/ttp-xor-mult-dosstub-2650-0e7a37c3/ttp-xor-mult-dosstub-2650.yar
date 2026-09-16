rule TTP_XOR_MULT_DOSStub_2650 {
  strings:
    $key_2650 = { 72 38 [2] 06 20 [2] 41 22 [2] 06 33 [2] 48 3f [2] 44 35 [2] 53 3e [2] 48 70 [2] 75 }

  condition:
    any of them
}
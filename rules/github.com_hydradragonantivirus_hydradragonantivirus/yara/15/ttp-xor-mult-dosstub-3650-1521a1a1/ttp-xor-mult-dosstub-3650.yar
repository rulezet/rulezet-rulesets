rule TTP_XOR_MULT_DOSStub_3650 {
  strings:
    $key_3650 = { 62 38 [2] 16 20 [2] 51 22 [2] 16 33 [2] 58 3f [2] 54 35 [2] 43 3e [2] 58 70 [2] 65 }

  condition:
    any of them
}
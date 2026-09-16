rule TTP_XOR_MULT_DOSStub_1250 {
  strings:
    $key_1250 = { 46 38 [2] 32 20 [2] 75 22 [2] 32 33 [2] 7c 3f [2] 70 35 [2] 67 3e [2] 7c 70 [2] 41 }

  condition:
    any of them
}
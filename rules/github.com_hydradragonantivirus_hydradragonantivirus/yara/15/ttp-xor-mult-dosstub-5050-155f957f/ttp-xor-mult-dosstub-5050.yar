rule TTP_XOR_MULT_DOSStub_5050 {
  strings:
    $key_5050 = { 04 38 [2] 70 20 [2] 37 22 [2] 70 33 [2] 3e 3f [2] 32 35 [2] 25 3e [2] 3e 70 [2] 03 }

  condition:
    any of them
}
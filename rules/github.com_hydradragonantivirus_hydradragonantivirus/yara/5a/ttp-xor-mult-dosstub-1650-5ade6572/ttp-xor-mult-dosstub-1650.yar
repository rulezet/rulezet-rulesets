rule TTP_XOR_MULT_DOSStub_1650 {
  strings:
    $key_1650 = { 42 38 [2] 36 20 [2] 71 22 [2] 36 33 [2] 78 3f [2] 74 35 [2] 63 3e [2] 78 70 [2] 45 }

  condition:
    any of them
}
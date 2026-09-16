rule TTP_XOR_MULT_DOSStub_1850 {
  strings:
    $key_1850 = { 4c 38 [2] 38 20 [2] 7f 22 [2] 38 33 [2] 76 3f [2] 7a 35 [2] 6d 3e [2] 76 70 [2] 4b }

  condition:
    any of them
}
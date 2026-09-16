rule TTP_XOR_MULT_DOSStub_1856 {
  strings:
    $key_1856 = { 4c 3e [2] 38 26 [2] 7f 24 [2] 38 35 [2] 76 39 [2] 7a 33 [2] 6d 38 [2] 76 76 [2] 4b }

  condition:
    any of them
}
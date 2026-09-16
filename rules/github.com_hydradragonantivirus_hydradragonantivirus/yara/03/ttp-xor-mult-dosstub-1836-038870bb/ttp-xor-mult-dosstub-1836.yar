rule TTP_XOR_MULT_DOSStub_1836 {
  strings:
    $key_1836 = { 4c 5e [2] 38 46 [2] 7f 44 [2] 38 55 [2] 76 59 [2] 7a 53 [2] 6d 58 [2] 76 16 [2] 4b }

  condition:
    any of them
}
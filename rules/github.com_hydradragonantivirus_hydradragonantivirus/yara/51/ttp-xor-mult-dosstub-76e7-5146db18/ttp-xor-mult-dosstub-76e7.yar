rule TTP_XOR_MULT_DOSStub_76e7 {
  strings:
    $key_76e7 = { 22 8f [2] 56 97 [2] 11 95 [2] 56 84 [2] 18 88 [2] 14 82 [2] 03 89 [2] 18 c7 [2] 25 }

  condition:
    any of them
}
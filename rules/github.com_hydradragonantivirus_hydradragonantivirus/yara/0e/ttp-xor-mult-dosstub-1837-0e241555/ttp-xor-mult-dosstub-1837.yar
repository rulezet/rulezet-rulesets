rule TTP_XOR_MULT_DOSStub_1837 {
  strings:
    $key_1837 = { 4c 5f [2] 38 47 [2] 7f 45 [2] 38 54 [2] 76 58 [2] 7a 52 [2] 6d 59 [2] 76 17 [2] 4b }

  condition:
    any of them
}
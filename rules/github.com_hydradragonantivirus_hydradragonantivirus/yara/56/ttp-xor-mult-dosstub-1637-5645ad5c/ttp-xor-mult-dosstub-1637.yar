rule TTP_XOR_MULT_DOSStub_1637 {
  strings:
    $key_1637 = { 42 5f [2] 36 47 [2] 71 45 [2] 36 54 [2] 78 58 [2] 74 52 [2] 63 59 [2] 78 17 [2] 45 }

  condition:
    any of them
}
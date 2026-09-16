rule TTP_XOR_MULT_DOSStub_7637 {
  strings:
    $key_7637 = { 22 5f [2] 56 47 [2] 11 45 [2] 56 54 [2] 18 58 [2] 14 52 [2] 03 59 [2] 18 17 [2] 25 }

  condition:
    any of them
}
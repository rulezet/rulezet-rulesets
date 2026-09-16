rule TTP_XOR_MULT_DOSStub_7667 {
  strings:
    $key_7667 = { 22 0f [2] 56 17 [2] 11 15 [2] 56 04 [2] 18 08 [2] 14 02 [2] 03 09 [2] 18 47 [2] 25 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_7651 {
  strings:
    $key_7651 = { 22 39 [2] 56 21 [2] 11 23 [2] 56 32 [2] 18 3e [2] 14 34 [2] 03 3f [2] 18 71 [2] 25 }

  condition:
    any of them
}
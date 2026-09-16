rule TTP_XOR_MULT_DOSStub_1677 {
  strings:
    $key_1677 = { 42 1f [2] 36 07 [2] 71 05 [2] 36 14 [2] 78 18 [2] 74 12 [2] 63 19 [2] 78 57 [2] 45 }

  condition:
    any of them
}
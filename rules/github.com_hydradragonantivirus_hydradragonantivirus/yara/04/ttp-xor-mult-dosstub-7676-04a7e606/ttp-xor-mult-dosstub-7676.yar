rule TTP_XOR_MULT_DOSStub_7676 {
  strings:
    $key_7676 = { 22 1e [2] 56 06 [2] 11 04 [2] 56 15 [2] 18 19 [2] 14 13 [2] 03 18 [2] 18 56 [2] 25 }

  condition:
    any of them
}
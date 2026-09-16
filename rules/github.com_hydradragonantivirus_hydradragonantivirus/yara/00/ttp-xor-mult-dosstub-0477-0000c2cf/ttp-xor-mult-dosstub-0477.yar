rule TTP_XOR_MULT_DOSStub_0477 {
  strings:
    $key_0477 = { 50 1f [2] 24 07 [2] 63 05 [2] 24 14 [2] 6a 18 [2] 66 12 [2] 71 19 [2] 6a 57 [2] 57 }

  condition:
    any of them
}
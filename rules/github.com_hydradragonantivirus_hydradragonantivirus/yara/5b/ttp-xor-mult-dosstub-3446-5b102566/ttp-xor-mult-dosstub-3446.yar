rule TTP_XOR_MULT_DOSStub_3446 {
  strings:
    $key_3446 = { 60 2e [2] 14 36 [2] 53 34 [2] 14 25 [2] 5a 29 [2] 56 23 [2] 41 28 [2] 5a 66 [2] 67 }

  condition:
    any of them
}
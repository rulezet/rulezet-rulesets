rule TTP_XOR_MULT_DOSStub_3441 {
  strings:
    $key_3441 = { 60 29 [2] 14 31 [2] 53 33 [2] 14 22 [2] 5a 2e [2] 56 24 [2] 41 2f [2] 5a 61 [2] 67 }

  condition:
    any of them
}
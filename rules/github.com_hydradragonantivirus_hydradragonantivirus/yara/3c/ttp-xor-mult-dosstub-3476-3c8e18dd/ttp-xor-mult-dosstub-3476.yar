rule TTP_XOR_MULT_DOSStub_3476 {
  strings:
    $key_3476 = { 60 1e [2] 14 06 [2] 53 04 [2] 14 15 [2] 5a 19 [2] 56 13 [2] 41 18 [2] 5a 56 [2] 67 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_33e7 {
  strings:
    $key_33e7 = { 67 8f [2] 13 97 [2] 54 95 [2] 13 84 [2] 5d 88 [2] 51 82 [2] 46 89 [2] 5d c7 [2] 60 }

  condition:
    any of them
}
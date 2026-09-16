rule TTP_XOR_MULT_DOSStub_13e7 {
  strings:
    $key_13e7 = { 47 8f [2] 33 97 [2] 74 95 [2] 33 84 [2] 7d 88 [2] 71 82 [2] 66 89 [2] 7d c7 [2] 40 }

  condition:
    any of them
}
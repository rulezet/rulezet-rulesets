rule TTP_XOR_MULT_DOSStub_64e7 {
  strings:
    $key_64e7 = { 30 8f [2] 44 97 [2] 03 95 [2] 44 84 [2] 0a 88 [2] 06 82 [2] 11 89 [2] 0a c7 [2] 37 }

  condition:
    any of them
}
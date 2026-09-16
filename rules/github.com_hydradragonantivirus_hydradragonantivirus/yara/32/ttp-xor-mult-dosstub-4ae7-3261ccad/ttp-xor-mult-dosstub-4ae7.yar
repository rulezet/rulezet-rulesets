rule TTP_XOR_MULT_DOSStub_4ae7 {
  strings:
    $key_4ae7 = { 1e 8f [2] 6a 97 [2] 2d 95 [2] 6a 84 [2] 24 88 [2] 28 82 [2] 3f 89 [2] 24 c7 [2] 19 }

  condition:
    any of them
}
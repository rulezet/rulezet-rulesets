rule TTP_XOR_MULT_DOSStub_4fe7 {
  strings:
    $key_4fe7 = { 1b 8f [2] 6f 97 [2] 28 95 [2] 6f 84 [2] 21 88 [2] 2d 82 [2] 3a 89 [2] 21 c7 [2] 1c }

  condition:
    any of them
}
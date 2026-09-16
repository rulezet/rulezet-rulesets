rule TTP_XOR_MULT_DOSStub_0fe7 {
  strings:
    $key_0fe7 = { 5b 8f [2] 2f 97 [2] 68 95 [2] 2f 84 [2] 61 88 [2] 6d 82 [2] 7a 89 [2] 61 c7 [2] 5c }

  condition:
    any of them
}
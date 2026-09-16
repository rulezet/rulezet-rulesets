rule TTP_XOR_MULT_DOSStub_1ae7 {
  strings:
    $key_1ae7 = { 4e 8f [2] 3a 97 [2] 7d 95 [2] 3a 84 [2] 74 88 [2] 78 82 [2] 6f 89 [2] 74 c7 [2] 49 }

  condition:
    any of them
}
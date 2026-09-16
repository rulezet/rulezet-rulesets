rule TTP_XOR_MULT_DOSStub_2ae7 {
  strings:
    $key_2ae7 = { 7e 8f [2] 0a 97 [2] 4d 95 [2] 0a 84 [2] 44 88 [2] 48 82 [2] 5f 89 [2] 44 c7 [2] 79 }

  condition:
    any of them
}
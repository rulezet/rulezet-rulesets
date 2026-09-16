rule TTP_XOR_MULT_DOSStub_2fe7 {
  strings:
    $key_2fe7 = { 7b 8f [2] 0f 97 [2] 48 95 [2] 0f 84 [2] 41 88 [2] 4d 82 [2] 5a 89 [2] 41 c7 [2] 7c }

  condition:
    any of them
}
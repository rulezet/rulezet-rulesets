rule TTP_XOR_MULT_DOSStub_2de7 {
  strings:
    $key_2de7 = { 79 8f [2] 0d 97 [2] 4a 95 [2] 0d 84 [2] 43 88 [2] 4f 82 [2] 58 89 [2] 43 c7 [2] 7e }

  condition:
    any of them
}
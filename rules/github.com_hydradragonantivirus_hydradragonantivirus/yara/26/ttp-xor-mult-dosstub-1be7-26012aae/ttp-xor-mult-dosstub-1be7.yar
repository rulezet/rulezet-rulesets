rule TTP_XOR_MULT_DOSStub_1be7 {
  strings:
    $key_1be7 = { 4f 8f [2] 3b 97 [2] 7c 95 [2] 3b 84 [2] 75 88 [2] 79 82 [2] 6e 89 [2] 75 c7 [2] 48 }

  condition:
    any of them
}
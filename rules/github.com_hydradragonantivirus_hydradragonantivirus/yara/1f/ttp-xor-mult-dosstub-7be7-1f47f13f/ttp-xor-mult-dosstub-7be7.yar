rule TTP_XOR_MULT_DOSStub_7be7 {
  strings:
    $key_7be7 = { 2f 8f [2] 5b 97 [2] 1c 95 [2] 5b 84 [2] 15 88 [2] 19 82 [2] 0e 89 [2] 15 c7 [2] 28 }

  condition:
    any of them
}
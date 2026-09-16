rule TTP_XOR_MULT_DOSStub_3de7 {
  strings:
    $key_3de7 = { 69 8f [2] 1d 97 [2] 5a 95 [2] 1d 84 [2] 53 88 [2] 5f 82 [2] 48 89 [2] 53 c7 [2] 6e }

  condition:
    any of them
}
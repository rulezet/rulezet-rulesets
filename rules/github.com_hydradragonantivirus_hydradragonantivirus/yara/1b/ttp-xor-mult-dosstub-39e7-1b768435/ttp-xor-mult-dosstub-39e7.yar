rule TTP_XOR_MULT_DOSStub_39e7 {
  strings:
    $key_39e7 = { 6d 8f [2] 19 97 [2] 5e 95 [2] 19 84 [2] 57 88 [2] 5b 82 [2] 4c 89 [2] 57 c7 [2] 6a }

  condition:
    any of them
}
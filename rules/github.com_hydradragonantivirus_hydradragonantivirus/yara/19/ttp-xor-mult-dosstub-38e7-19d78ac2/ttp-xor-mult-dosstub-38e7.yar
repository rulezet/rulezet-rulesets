rule TTP_XOR_MULT_DOSStub_38e7 {
  strings:
    $key_38e7 = { 6c 8f [2] 18 97 [2] 5f 95 [2] 18 84 [2] 56 88 [2] 5a 82 [2] 4d 89 [2] 56 c7 [2] 6b }

  condition:
    any of them
}
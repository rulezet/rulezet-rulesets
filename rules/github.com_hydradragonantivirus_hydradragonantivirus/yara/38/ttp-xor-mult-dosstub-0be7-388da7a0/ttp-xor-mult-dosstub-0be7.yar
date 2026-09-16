rule TTP_XOR_MULT_DOSStub_0be7 {
  strings:
    $key_0be7 = { 5f 8f [2] 2b 97 [2] 6c 95 [2] 2b 84 [2] 65 88 [2] 69 82 [2] 7e 89 [2] 65 c7 [2] 58 }

  condition:
    any of them
}
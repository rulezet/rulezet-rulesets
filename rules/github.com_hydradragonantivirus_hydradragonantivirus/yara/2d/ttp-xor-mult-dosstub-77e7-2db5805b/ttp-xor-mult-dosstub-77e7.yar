rule TTP_XOR_MULT_DOSStub_77e7 {
  strings:
    $key_77e7 = { 23 8f [2] 57 97 [2] 10 95 [2] 57 84 [2] 19 88 [2] 15 82 [2] 02 89 [2] 19 c7 [2] 24 }

  condition:
    any of them
}
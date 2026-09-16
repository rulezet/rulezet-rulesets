rule TTP_XOR_MULT_DOSStub_56e7 {
  strings:
    $key_56e7 = { 02 8f [2] 76 97 [2] 31 95 [2] 76 84 [2] 38 88 [2] 34 82 [2] 23 89 [2] 38 c7 [2] 05 }

  condition:
    any of them
}
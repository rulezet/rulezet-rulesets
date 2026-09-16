rule TTP_XOR_MULT_DOSStub_10e7 {
  strings:
    $key_10e7 = { 44 8f [2] 30 97 [2] 77 95 [2] 30 84 [2] 7e 88 [2] 72 82 [2] 65 89 [2] 7e c7 [2] 43 }

  condition:
    any of them
}
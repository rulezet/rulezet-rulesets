rule TTP_XOR_MULT_DOSStub_25e7 {
  strings:
    $key_25e7 = { 71 8f [2] 05 97 [2] 42 95 [2] 05 84 [2] 4b 88 [2] 47 82 [2] 50 89 [2] 4b c7 [2] 76 }

  condition:
    any of them
}
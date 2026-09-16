rule TTP_XOR_MULT_DOSStub_15e7 {
  strings:
    $key_15e7 = { 41 8f [2] 35 97 [2] 72 95 [2] 35 84 [2] 7b 88 [2] 77 82 [2] 60 89 [2] 7b c7 [2] 46 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_07e7 {
  strings:
    $key_07e7 = { 53 8f [2] 27 97 [2] 60 95 [2] 27 84 [2] 69 88 [2] 65 82 [2] 72 89 [2] 69 c7 [2] 54 }

  condition:
    any of them
}
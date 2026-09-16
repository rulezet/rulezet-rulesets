rule TTP_XOR_MULT_DOSStub_7af0 {
  strings:
    $key_7af0 = { 2e 98 [2] 5a 80 [2] 1d 82 [2] 5a 93 [2] 14 9f [2] 18 95 [2] 0f 9e [2] 14 d0 [2] 29 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_37e7 {
  strings:
    $key_37e7 = { 63 8f [2] 17 97 [2] 50 95 [2] 17 84 [2] 59 88 [2] 55 82 [2] 42 89 [2] 59 c7 [2] 64 }

  condition:
    any of them
}
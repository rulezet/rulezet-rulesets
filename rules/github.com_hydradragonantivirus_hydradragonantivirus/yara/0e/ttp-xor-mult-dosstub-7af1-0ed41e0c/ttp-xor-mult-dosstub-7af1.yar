rule TTP_XOR_MULT_DOSStub_7af1 {
  strings:
    $key_7af1 = { 2e 99 [2] 5a 81 [2] 1d 83 [2] 5a 92 [2] 14 9e [2] 18 94 [2] 0f 9f [2] 14 d1 [2] 29 }

  condition:
    any of them
}
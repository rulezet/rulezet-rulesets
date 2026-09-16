rule TTP_XOR_MULT_DOSStub_7a40 {
  strings:
    $key_7a40 = { 2e 28 [2] 5a 30 [2] 1d 32 [2] 5a 23 [2] 14 2f [2] 18 25 [2] 0f 2e [2] 14 60 [2] 29 }

  condition:
    any of them
}
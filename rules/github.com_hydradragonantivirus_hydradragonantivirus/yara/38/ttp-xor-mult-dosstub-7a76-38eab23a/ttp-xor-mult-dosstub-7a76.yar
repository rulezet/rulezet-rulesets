rule TTP_XOR_MULT_DOSStub_7a76 {
  strings:
    $key_7a76 = { 2e 1e [2] 5a 06 [2] 1d 04 [2] 5a 15 [2] 14 19 [2] 18 13 [2] 0f 18 [2] 14 56 [2] 29 }

  condition:
    any of them
}
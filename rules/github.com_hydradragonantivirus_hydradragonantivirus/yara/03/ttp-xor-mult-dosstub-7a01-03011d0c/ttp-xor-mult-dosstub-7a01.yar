rule TTP_XOR_MULT_DOSStub_7a01 {
  strings:
    $key_7a01 = { 2e 69 [2] 5a 71 [2] 1d 73 [2] 5a 62 [2] 14 6e [2] 18 64 [2] 0f 6f [2] 14 21 [2] 29 }

  condition:
    any of them
}
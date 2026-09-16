rule TTP_XOR_MULT_DOSStub_4401 {
  strings:
    $key_4401 = { 10 69 [2] 64 71 [2] 23 73 [2] 64 62 [2] 2a 6e [2] 26 64 [2] 31 6f [2] 2a 21 [2] 17 }

  condition:
    any of them
}
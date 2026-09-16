rule TTP_XOR_MULT_DOSStub_4456 {
  strings:
    $key_4456 = { 10 3e [2] 64 26 [2] 23 24 [2] 64 35 [2] 2a 39 [2] 26 33 [2] 31 38 [2] 2a 76 [2] 17 }

  condition:
    any of them
}
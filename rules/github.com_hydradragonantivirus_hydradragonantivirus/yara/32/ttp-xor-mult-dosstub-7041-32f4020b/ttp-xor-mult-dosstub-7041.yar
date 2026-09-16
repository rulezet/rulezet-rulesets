rule TTP_XOR_MULT_DOSStub_7041 {
  strings:
    $key_7041 = { 24 29 [2] 50 31 [2] 17 33 [2] 50 22 [2] 1e 2e [2] 12 24 [2] 05 2f [2] 1e 61 [2] 23 }

  condition:
    any of them
}
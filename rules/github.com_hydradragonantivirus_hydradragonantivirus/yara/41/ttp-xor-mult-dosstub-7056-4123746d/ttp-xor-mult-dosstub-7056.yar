rule TTP_XOR_MULT_DOSStub_7056 {
  strings:
    $key_7056 = { 24 3e [2] 50 26 [2] 17 24 [2] 50 35 [2] 1e 39 [2] 12 33 [2] 05 38 [2] 1e 76 [2] 23 }

  condition:
    any of them
}
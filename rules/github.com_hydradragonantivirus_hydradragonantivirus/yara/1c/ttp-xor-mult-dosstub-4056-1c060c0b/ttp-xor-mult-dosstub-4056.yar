rule TTP_XOR_MULT_DOSStub_4056 {
  strings:
    $key_4056 = { 14 3e [2] 60 26 [2] 27 24 [2] 60 35 [2] 2e 39 [2] 22 33 [2] 35 38 [2] 2e 76 [2] 13 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1056 {
  strings:
    $key_1056 = { 44 3e [2] 30 26 [2] 77 24 [2] 30 35 [2] 7e 39 [2] 72 33 [2] 65 38 [2] 7e 76 [2] 43 }

  condition:
    any of them
}
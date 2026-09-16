rule TTP_XOR_MULT_DOSStub_3056 {
  strings:
    $key_3056 = { 64 3e [2] 10 26 [2] 57 24 [2] 10 35 [2] 5e 39 [2] 52 33 [2] 45 38 [2] 5e 76 [2] 63 }

  condition:
    any of them
}
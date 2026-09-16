rule TTP_XOR_MULT_DOSStub_5056 {
  strings:
    $key_5056 = { 04 3e [2] 70 26 [2] 37 24 [2] 70 35 [2] 3e 39 [2] 32 33 [2] 25 38 [2] 3e 76 [2] 03 }

  condition:
    any of them
}
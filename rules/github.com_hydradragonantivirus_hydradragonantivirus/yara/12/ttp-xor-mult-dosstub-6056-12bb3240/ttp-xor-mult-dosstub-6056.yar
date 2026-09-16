rule TTP_XOR_MULT_DOSStub_6056 {
  strings:
    $key_6056 = { 34 3e [2] 40 26 [2] 07 24 [2] 40 35 [2] 0e 39 [2] 02 33 [2] 15 38 [2] 0e 76 [2] 33 }

  condition:
    any of them
}
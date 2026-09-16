rule TTP_XOR_MULT_DOSStub_0a56 {
  strings:
    $key_0a56 = { 5e 3e [2] 2a 26 [2] 6d 24 [2] 2a 35 [2] 64 39 [2] 68 33 [2] 7f 38 [2] 64 76 [2] 59 }

  condition:
    any of them
}
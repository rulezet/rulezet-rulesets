rule TTP_XOR_MULT_DOSStub_4651 {
  strings:
    $key_4651 = { 12 39 [2] 66 21 [2] 21 23 [2] 66 32 [2] 28 3e [2] 24 34 [2] 33 3f [2] 28 71 [2] 15 }

  condition:
    any of them
}
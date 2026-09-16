rule TTP_XOR_MULT_DOSStub_3551 {
  strings:
    $key_3551 = { 61 39 [2] 15 21 [2] 52 23 [2] 15 32 [2] 5b 3e [2] 57 34 [2] 40 3f [2] 5b 71 [2] 66 }

  condition:
    any of them
}
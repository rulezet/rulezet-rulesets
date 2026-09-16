rule TTP_XOR_MULT_DOSStub_3451 {
  strings:
    $key_3451 = { 60 39 [2] 14 21 [2] 53 23 [2] 14 32 [2] 5a 3e [2] 56 34 [2] 41 3f [2] 5a 71 [2] 67 }

  condition:
    any of them
}
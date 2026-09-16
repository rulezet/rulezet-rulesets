rule TTP_XOR_MULT_DOSStub_0551 {
  strings:
    $key_0551 = { 51 39 [2] 25 21 [2] 62 23 [2] 25 32 [2] 6b 3e [2] 67 34 [2] 70 3f [2] 6b 71 [2] 56 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0546 {
  strings:
    $key_0546 = { 51 2e [2] 25 36 [2] 62 34 [2] 25 25 [2] 6b 29 [2] 67 23 [2] 70 28 [2] 6b 66 [2] 56 }

  condition:
    any of them
}
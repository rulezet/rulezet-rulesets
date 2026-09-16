rule TTP_XOR_MULT_DOSStub_0331 {
  strings:
    $key_0331 = { 57 59 [2] 23 41 [2] 64 43 [2] 23 52 [2] 6d 5e [2] 61 54 [2] 76 5f [2] 6d 11 [2] 50 }

  condition:
    any of them
}
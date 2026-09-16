rule TTP_XOR_MULT_DOSStub_0337 {
  strings:
    $key_0337 = { 57 5f [2] 23 47 [2] 64 45 [2] 23 54 [2] 6d 58 [2] 61 52 [2] 76 59 [2] 6d 17 [2] 50 }

  condition:
    any of them
}
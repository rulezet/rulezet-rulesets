rule TTP_XOR_MULT_DOSStub_0320 {
  strings:
    $key_0320 = { 57 48 [2] 23 50 [2] 64 52 [2] 23 43 [2] 6d 4f [2] 61 45 [2] 76 4e [2] 6d 00 [2] 50 }

  condition:
    any of them
}
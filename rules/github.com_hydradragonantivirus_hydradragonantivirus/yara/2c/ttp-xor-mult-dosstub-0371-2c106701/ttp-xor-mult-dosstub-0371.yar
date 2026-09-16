rule TTP_XOR_MULT_DOSStub_0371 {
  strings:
    $key_0371 = { 57 19 [2] 23 01 [2] 64 03 [2] 23 12 [2] 6d 1e [2] 61 14 [2] 76 1f [2] 6d 51 [2] 50 }

  condition:
    any of them
}
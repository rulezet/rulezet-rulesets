rule TTP_XOR_MULT_DOSStub_6857 {
  strings:
    $key_6857 = { 3c 3f [2] 48 27 [2] 0f 25 [2] 48 34 [2] 06 38 [2] 0a 32 [2] 1d 39 [2] 06 77 [2] 3b }

  condition:
    any of them
}
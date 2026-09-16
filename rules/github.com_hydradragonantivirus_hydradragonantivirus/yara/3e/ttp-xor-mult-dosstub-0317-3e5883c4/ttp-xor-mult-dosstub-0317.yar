rule TTP_XOR_MULT_DOSStub_0317 {
  strings:
    $key_0317 = { 57 7f [2] 23 67 [2] 64 65 [2] 23 74 [2] 6d 78 [2] 61 72 [2] 76 79 [2] 6d 37 [2] 50 }

  condition:
    any of them
}
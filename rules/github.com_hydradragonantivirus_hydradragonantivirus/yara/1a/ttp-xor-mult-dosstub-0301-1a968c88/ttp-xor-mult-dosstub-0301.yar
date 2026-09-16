rule TTP_XOR_MULT_DOSStub_0301 {
  strings:
    $key_0301 = { 57 69 [2] 23 71 [2] 64 73 [2] 23 62 [2] 6d 6e [2] 61 64 [2] 76 6f [2] 6d 21 [2] 50 }

  condition:
    any of them
}
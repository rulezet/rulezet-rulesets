rule TTP_XOR_MULT_DOSStub_6801 {
  strings:
    $key_6801 = { 3c 69 [2] 48 71 [2] 0f 73 [2] 48 62 [2] 06 6e [2] 0a 64 [2] 1d 6f [2] 06 21 [2] 3b }

  condition:
    any of them
}
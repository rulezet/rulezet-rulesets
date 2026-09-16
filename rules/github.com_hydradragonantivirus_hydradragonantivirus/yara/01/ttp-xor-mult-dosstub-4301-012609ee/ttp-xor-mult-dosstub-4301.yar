rule TTP_XOR_MULT_DOSStub_4301 {
  strings:
    $key_4301 = { 17 69 [2] 63 71 [2] 24 73 [2] 63 62 [2] 2d 6e [2] 21 64 [2] 36 6f [2] 2d 21 [2] 10 }

  condition:
    any of them
}
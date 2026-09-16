rule TTP_XOR_MULT_DOSStub_7301 {
  strings:
    $key_7301 = { 27 69 [2] 53 71 [2] 14 73 [2] 53 62 [2] 1d 6e [2] 11 64 [2] 06 6f [2] 1d 21 [2] 20 }

  condition:
    any of them
}
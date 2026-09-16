rule TTP_XOR_MULT_DOSStub_6301 {
  strings:
    $key_6301 = { 37 69 [2] 43 71 [2] 04 73 [2] 43 62 [2] 0d 6e [2] 01 64 [2] 16 6f [2] 0d 21 [2] 30 }

  condition:
    any of them
}
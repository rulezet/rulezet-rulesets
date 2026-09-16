rule TTP_XOR_MULT_DOSStub_7901 {
  strings:
    $key_7901 = { 2d 69 [2] 59 71 [2] 1e 73 [2] 59 62 [2] 17 6e [2] 1b 64 [2] 0c 6f [2] 17 21 [2] 2a }

  condition:
    any of them
}
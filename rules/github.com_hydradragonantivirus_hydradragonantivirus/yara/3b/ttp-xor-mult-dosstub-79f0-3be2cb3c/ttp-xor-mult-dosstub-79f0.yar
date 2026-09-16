rule TTP_XOR_MULT_DOSStub_79f0 {
  strings:
    $key_79f0 = { 2d 98 [2] 59 80 [2] 1e 82 [2] 59 93 [2] 17 9f [2] 1b 95 [2] 0c 9e [2] 17 d0 [2] 2a }

  condition:
    any of them
}
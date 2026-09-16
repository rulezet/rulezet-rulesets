rule TTP_XOR_MULT_DOSStub_7910 {
  strings:
    $key_7910 = { 2d 78 [2] 59 60 [2] 1e 62 [2] 59 73 [2] 17 7f [2] 1b 75 [2] 0c 7e [2] 17 30 [2] 2a }

  condition:
    any of them
}
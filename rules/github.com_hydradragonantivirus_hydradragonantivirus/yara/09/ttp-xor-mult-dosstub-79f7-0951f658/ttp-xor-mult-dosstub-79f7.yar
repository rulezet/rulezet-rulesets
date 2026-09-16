rule TTP_XOR_MULT_DOSStub_79f7 {
  strings:
    $key_79f7 = { 2d 9f [2] 59 87 [2] 1e 85 [2] 59 94 [2] 17 98 [2] 1b 92 [2] 0c 99 [2] 17 d7 [2] 2a }

  condition:
    any of them
}
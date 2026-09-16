rule TTP_XOR_MULT_DOSStub_4cf0 {
  strings:
    $key_4cf0 = { 18 98 [2] 6c 80 [2] 2b 82 [2] 6c 93 [2] 22 9f [2] 2e 95 [2] 39 9e [2] 22 d0 [2] 1f }

  condition:
    any of them
}
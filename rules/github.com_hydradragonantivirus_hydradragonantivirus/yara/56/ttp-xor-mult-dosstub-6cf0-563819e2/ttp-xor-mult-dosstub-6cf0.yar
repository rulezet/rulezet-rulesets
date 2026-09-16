rule TTP_XOR_MULT_DOSStub_6cf0 {
  strings:
    $key_6cf0 = { 38 98 [2] 4c 80 [2] 0b 82 [2] 4c 93 [2] 02 9f [2] 0e 95 [2] 19 9e [2] 02 d0 [2] 3f }

  condition:
    any of them
}
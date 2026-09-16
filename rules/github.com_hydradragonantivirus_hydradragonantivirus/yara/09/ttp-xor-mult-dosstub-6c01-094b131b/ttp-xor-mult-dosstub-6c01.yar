rule TTP_XOR_MULT_DOSStub_6c01 {
  strings:
    $key_6c01 = { 38 69 [2] 4c 71 [2] 0b 73 [2] 4c 62 [2] 02 6e [2] 0e 64 [2] 19 6f [2] 02 21 [2] 3f }

  condition:
    any of them
}
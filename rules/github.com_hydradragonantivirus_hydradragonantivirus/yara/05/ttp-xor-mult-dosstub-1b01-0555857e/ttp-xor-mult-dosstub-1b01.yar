rule TTP_XOR_MULT_DOSStub_1b01 {
  strings:
    $key_1b01 = { 4f 69 [2] 3b 71 [2] 7c 73 [2] 3b 62 [2] 75 6e [2] 79 64 [2] 6e 6f [2] 75 21 [2] 48 }

  condition:
    any of them
}
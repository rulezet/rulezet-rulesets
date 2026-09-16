rule TTP_XOR_MULT_DOSStub_1b71 {
  strings:
    $key_1b71 = { 4f 19 [2] 3b 01 [2] 7c 03 [2] 3b 12 [2] 75 1e [2] 79 14 [2] 6e 1f [2] 75 51 [2] 48 }

  condition:
    any of them
}
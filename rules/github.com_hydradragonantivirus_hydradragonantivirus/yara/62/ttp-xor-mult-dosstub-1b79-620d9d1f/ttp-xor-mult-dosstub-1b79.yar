rule TTP_XOR_MULT_DOSStub_1b79 {
  strings:
    $key_1b79 = { 4f 11 [2] 3b 09 [2] 7c 0b [2] 3b 1a [2] 75 16 [2] 79 1c [2] 6e 17 [2] 75 59 [2] 48 }

  condition:
    any of them
}
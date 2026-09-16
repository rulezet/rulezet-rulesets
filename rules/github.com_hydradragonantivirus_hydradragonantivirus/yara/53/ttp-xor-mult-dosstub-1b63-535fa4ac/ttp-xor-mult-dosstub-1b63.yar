rule TTP_XOR_MULT_DOSStub_1b63 {
  strings:
    $key_1b63 = { 4f 0b [2] 3b 13 [2] 7c 11 [2] 3b 00 [2] 75 0c [2] 79 06 [2] 6e 0d [2] 75 43 [2] 48 }

  condition:
    any of them
}
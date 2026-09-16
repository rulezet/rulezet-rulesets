rule TTP_XOR_MULT_DOSStub_1b65 {
  strings:
    $key_1b65 = { 4f 0d [2] 3b 15 [2] 7c 17 [2] 3b 06 [2] 75 0a [2] 79 00 [2] 6e 0b [2] 75 45 [2] 48 }

  condition:
    any of them
}
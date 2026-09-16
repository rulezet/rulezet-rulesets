rule TTP_XOR_MULT_DOSStub_1b68 {
  strings:
    $key_1b68 = { 4f 00 [2] 3b 18 [2] 7c 1a [2] 3b 0b [2] 75 07 [2] 79 0d [2] 6e 06 [2] 75 48 [2] 48 }

  condition:
    any of them
}
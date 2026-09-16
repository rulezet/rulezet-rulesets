rule TTP_XOR_MULT_DOSStub_6c65 {
  strings:
    $key_6c65 = { 38 0d [2] 4c 15 [2] 0b 17 [2] 4c 06 [2] 02 0a [2] 0e 00 [2] 19 0b [2] 02 45 [2] 3f }

  condition:
    any of them
}
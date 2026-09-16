rule TTP_XOR_MULT_DOSStub_2a65 {
  strings:
    $key_2a65 = { 7e 0d [2] 0a 15 [2] 4d 17 [2] 0a 06 [2] 44 0a [2] 48 00 [2] 5f 0b [2] 44 45 [2] 79 }

  condition:
    any of them
}
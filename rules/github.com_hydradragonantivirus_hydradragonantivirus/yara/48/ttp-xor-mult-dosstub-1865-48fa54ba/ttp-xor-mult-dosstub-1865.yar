rule TTP_XOR_MULT_DOSStub_1865 {
  strings:
    $key_1865 = { 4c 0d [2] 38 15 [2] 7f 17 [2] 38 06 [2] 76 0a [2] 7a 00 [2] 6d 0b [2] 76 45 [2] 4b }

  condition:
    any of them
}
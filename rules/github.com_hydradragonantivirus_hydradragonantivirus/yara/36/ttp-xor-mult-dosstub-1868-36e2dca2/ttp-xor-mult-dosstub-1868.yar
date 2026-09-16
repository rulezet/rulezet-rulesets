rule TTP_XOR_MULT_DOSStub_1868 {
  strings:
    $key_1868 = { 4c 00 [2] 38 18 [2] 7f 1a [2] 38 0b [2] 76 07 [2] 7a 0d [2] 6d 06 [2] 76 48 [2] 4b }

  condition:
    any of them
}
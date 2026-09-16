rule TTP_XOR_MULT_DOSStub_3a69 {
  strings:
    $key_3a69 = { 6e 01 [2] 1a 19 [2] 5d 1b [2] 1a 0a [2] 54 06 [2] 58 0c [2] 4f 07 [2] 54 49 [2] 69 }

  condition:
    any of them
}
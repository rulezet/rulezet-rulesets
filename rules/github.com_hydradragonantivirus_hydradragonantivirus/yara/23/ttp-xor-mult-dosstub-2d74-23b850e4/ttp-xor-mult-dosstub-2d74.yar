rule TTP_XOR_MULT_DOSStub_2d74 {
  strings:
    $key_2d74 = { 79 1c [2] 0d 04 [2] 4a 06 [2] 0d 17 [2] 43 1b [2] 4f 11 [2] 58 1a [2] 43 54 [2] 7e }

  condition:
    any of them
}
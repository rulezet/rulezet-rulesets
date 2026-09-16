rule TTP_XOR_MULT_DOSStub_7963 {
  strings:
    $key_7963 = { 2d 0b [2] 59 13 [2] 1e 11 [2] 59 00 [2] 17 0c [2] 1b 06 [2] 0c 0d [2] 17 43 [2] 2a }

  condition:
    any of them
}
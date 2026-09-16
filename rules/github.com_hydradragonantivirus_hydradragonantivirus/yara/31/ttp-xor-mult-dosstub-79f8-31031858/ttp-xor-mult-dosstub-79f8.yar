rule TTP_XOR_MULT_DOSStub_79f8 {
  strings:
    $key_79f8 = { 2d 90 [2] 59 88 [2] 1e 8a [2] 59 9b [2] 17 97 [2] 1b 9d [2] 0c 96 [2] 17 d8 [2] 2a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_79e5 {
  strings:
    $key_79e5 = { 2d 8d [2] 59 95 [2] 1e 97 [2] 59 86 [2] 17 8a [2] 1b 80 [2] 0c 8b [2] 17 c5 [2] 2a }

  condition:
    any of them
}
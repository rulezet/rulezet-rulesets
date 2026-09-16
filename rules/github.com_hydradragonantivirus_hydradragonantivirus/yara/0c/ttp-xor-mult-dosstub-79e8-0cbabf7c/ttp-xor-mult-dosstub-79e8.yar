rule TTP_XOR_MULT_DOSStub_79e8 {
  strings:
    $key_79e8 = { 2d 80 [2] 59 98 [2] 1e 9a [2] 59 8b [2] 17 87 [2] 1b 8d [2] 0c 86 [2] 17 c8 [2] 2a }

  condition:
    any of them
}
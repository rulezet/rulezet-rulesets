rule TTP_XOR_MULT_DOSStub_79e2 {
  strings:
    $key_79e2 = { 2d 8a [2] 59 92 [2] 1e 90 [2] 59 81 [2] 17 8d [2] 1b 87 [2] 0c 8c [2] 17 c2 [2] 2a }

  condition:
    any of them
}
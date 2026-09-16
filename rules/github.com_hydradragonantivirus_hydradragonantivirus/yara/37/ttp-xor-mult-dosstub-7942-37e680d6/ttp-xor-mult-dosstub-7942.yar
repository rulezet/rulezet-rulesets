rule TTP_XOR_MULT_DOSStub_7942 {
  strings:
    $key_7942 = { 2d 2a [2] 59 32 [2] 1e 30 [2] 59 21 [2] 17 2d [2] 1b 27 [2] 0c 2c [2] 17 62 [2] 2a }

  condition:
    any of them
}
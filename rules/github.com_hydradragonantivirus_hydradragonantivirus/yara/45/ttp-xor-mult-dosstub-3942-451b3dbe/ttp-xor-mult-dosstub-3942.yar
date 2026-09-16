rule TTP_XOR_MULT_DOSStub_3942 {
  strings:
    $key_3942 = { 6d 2a [2] 19 32 [2] 5e 30 [2] 19 21 [2] 57 2d [2] 5b 27 [2] 4c 2c [2] 57 62 [2] 6a }

  condition:
    any of them
}
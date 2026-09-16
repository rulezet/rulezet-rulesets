rule TTP_XOR_MULT_DOSStub_0942 {
  strings:
    $key_0942 = { 5d 2a [2] 29 32 [2] 6e 30 [2] 29 21 [2] 67 2d [2] 6b 27 [2] 7c 2c [2] 67 62 [2] 5a }

  condition:
    any of them
}
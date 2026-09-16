rule TTP_XOR_MULT_DOSStub_7843 {
  strings:
    $key_7843 = { 2c 2b [2] 58 33 [2] 1f 31 [2] 58 20 [2] 16 2c [2] 1a 26 [2] 0d 2d [2] 16 63 [2] 2b }

  condition:
    any of them
}
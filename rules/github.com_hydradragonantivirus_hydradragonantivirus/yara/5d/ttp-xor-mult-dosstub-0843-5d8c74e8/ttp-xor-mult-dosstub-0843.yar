rule TTP_XOR_MULT_DOSStub_0843 {
  strings:
    $key_0843 = { 5c 2b [2] 28 33 [2] 6f 31 [2] 28 20 [2] 66 2c [2] 6a 26 [2] 7d 2d [2] 66 63 [2] 5b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0844 {
  strings:
    $key_0844 = { 5c 2c [2] 28 34 [2] 6f 36 [2] 28 27 [2] 66 2b [2] 6a 21 [2] 7d 2a [2] 66 64 [2] 5b }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_0849 {
  strings:
    $key_0849 = { 5c 21 [2] 28 39 [2] 6f 3b [2] 28 2a [2] 66 26 [2] 6a 2c [2] 7d 27 [2] 66 69 [2] 5b }

  condition:
    any of them
}
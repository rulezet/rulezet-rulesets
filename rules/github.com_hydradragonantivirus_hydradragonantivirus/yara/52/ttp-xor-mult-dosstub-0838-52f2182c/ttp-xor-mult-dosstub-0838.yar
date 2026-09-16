rule TTP_XOR_MULT_DOSStub_0838 {
  strings:
    $key_0838 = { 5c 50 [2] 28 48 [2] 6f 4a [2] 28 5b [2] 66 57 [2] 6a 5d [2] 7d 56 [2] 66 18 [2] 5b }

  condition:
    any of them
}
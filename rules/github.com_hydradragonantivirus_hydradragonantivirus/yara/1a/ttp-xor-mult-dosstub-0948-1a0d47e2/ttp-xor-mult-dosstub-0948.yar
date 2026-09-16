rule TTP_XOR_MULT_DOSStub_0948 {
  strings:
    $key_0948 = { 5d 20 [2] 29 38 [2] 6e 3a [2] 29 2b [2] 67 27 [2] 6b 2d [2] 7c 26 [2] 67 68 [2] 5a }

  condition:
    any of them
}
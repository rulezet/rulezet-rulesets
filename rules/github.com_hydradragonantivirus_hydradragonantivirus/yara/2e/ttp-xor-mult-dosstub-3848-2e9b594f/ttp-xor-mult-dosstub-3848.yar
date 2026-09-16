rule TTP_XOR_MULT_DOSStub_3848 {
  strings:
    $key_3848 = { 6c 20 [2] 18 38 [2] 5f 3a [2] 18 2b [2] 56 27 [2] 5a 2d [2] 4d 26 [2] 56 68 [2] 6b }

  condition:
    any of them
}
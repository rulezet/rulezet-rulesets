rule TTP_XOR_MULT_DOSStub_4a33 {
  strings:
    $key_4a33 = { 1e 5b [2] 6a 43 [2] 2d 41 [2] 6a 50 [2] 24 5c [2] 28 56 [2] 3f 5d [2] 24 13 [2] 19 }

  condition:
    any of them
}
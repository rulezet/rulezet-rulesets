rule TTP_XOR_MULT_DOSStub_4a13 {
  strings:
    $key_4a13 = { 1e 7b [2] 6a 63 [2] 2d 61 [2] 6a 70 [2] 24 7c [2] 28 76 [2] 3f 7d [2] 24 33 [2] 19 }

  condition:
    any of them
}
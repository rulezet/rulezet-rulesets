rule TTP_XOR_MULT_DOSStub_4a15 {
  strings:
    $key_4a15 = { 1e 7d [2] 6a 65 [2] 2d 67 [2] 6a 76 [2] 24 7a [2] 28 70 [2] 3f 7b [2] 24 35 [2] 19 }

  condition:
    any of them
}
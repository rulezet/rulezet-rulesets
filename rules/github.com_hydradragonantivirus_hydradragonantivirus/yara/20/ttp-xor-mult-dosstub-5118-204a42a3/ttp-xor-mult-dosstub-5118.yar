rule TTP_XOR_MULT_DOSStub_5118 {
  strings:
    $key_5118 = { 05 70 [2] 71 68 [2] 36 6a [2] 71 7b [2] 3f 77 [2] 33 7d [2] 24 76 [2] 3f 38 [2] 02 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5a19 {
  strings:
    $key_5a19 = { 0e 71 [2] 7a 69 [2] 3d 6b [2] 7a 7a [2] 34 76 [2] 38 7c [2] 2f 77 [2] 34 39 [2] 09 }

  condition:
    any of them
}
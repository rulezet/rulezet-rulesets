rule TTP_XOR_MULT_DOSStub_5a18 {
  strings:
    $key_5a18 = { 0e 70 [2] 7a 68 [2] 3d 6a [2] 7a 7b [2] 34 77 [2] 38 7d [2] 2f 76 [2] 34 38 [2] 09 }

  condition:
    any of them
}
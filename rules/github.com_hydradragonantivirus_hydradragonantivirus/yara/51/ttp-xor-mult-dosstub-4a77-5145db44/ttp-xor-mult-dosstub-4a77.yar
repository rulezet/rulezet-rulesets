rule TTP_XOR_MULT_DOSStub_4a77 {
  strings:
    $key_4a77 = { 1e 1f [2] 6a 07 [2] 2d 05 [2] 6a 14 [2] 24 18 [2] 28 12 [2] 3f 19 [2] 24 57 [2] 19 }

  condition:
    any of them
}
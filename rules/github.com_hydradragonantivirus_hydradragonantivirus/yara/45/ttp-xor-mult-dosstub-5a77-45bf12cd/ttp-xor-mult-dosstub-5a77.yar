rule TTP_XOR_MULT_DOSStub_5a77 {
  strings:
    $key_5a77 = { 0e 1f [2] 7a 07 [2] 3d 05 [2] 7a 14 [2] 34 18 [2] 38 12 [2] 2f 19 [2] 34 57 [2] 09 }

  condition:
    any of them
}
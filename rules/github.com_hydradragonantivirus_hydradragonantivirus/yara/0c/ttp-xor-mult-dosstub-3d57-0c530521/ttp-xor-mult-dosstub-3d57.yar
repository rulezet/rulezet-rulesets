rule TTP_XOR_MULT_DOSStub_3d57 {
  strings:
    $key_3d57 = { 69 3f [2] 1d 27 [2] 5a 25 [2] 1d 34 [2] 53 38 [2] 5f 32 [2] 48 39 [2] 53 77 [2] 6e }

  condition:
    any of them
}
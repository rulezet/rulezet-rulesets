rule TTP_XOR_MULT_DOSStub_3d77 {
  strings:
    $key_3d77 = { 69 1f [2] 1d 07 [2] 5a 05 [2] 1d 14 [2] 53 18 [2] 5f 12 [2] 48 19 [2] 53 57 [2] 6e }

  condition:
    any of them
}
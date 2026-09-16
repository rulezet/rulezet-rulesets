rule TTP_XOR_MULT_DOSStub_3d18 {
  strings:
    $key_3d18 = { 69 70 [2] 1d 68 [2] 5a 6a [2] 1d 7b [2] 53 77 [2] 5f 7d [2] 48 76 [2] 53 38 [2] 6e }

  condition:
    any of them
}
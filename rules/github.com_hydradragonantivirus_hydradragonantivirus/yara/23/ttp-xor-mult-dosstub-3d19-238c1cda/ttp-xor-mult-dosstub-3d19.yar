rule TTP_XOR_MULT_DOSStub_3d19 {
  strings:
    $key_3d19 = { 69 71 [2] 1d 69 [2] 5a 6b [2] 1d 7a [2] 53 76 [2] 5f 7c [2] 48 77 [2] 53 39 [2] 6e }

  condition:
    any of them
}
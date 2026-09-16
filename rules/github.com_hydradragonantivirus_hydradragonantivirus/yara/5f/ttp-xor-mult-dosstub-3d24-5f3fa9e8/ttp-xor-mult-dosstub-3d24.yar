rule TTP_XOR_MULT_DOSStub_3d24 {
  strings:
    $key_3d24 = { 69 4c [2] 1d 54 [2] 5a 56 [2] 1d 47 [2] 53 4b [2] 5f 41 [2] 48 4a [2] 53 04 [2] 6e }

  condition:
    any of them
}
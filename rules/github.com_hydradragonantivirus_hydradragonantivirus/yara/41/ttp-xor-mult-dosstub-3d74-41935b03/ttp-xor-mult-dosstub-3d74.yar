rule TTP_XOR_MULT_DOSStub_3d74 {
  strings:
    $key_3d74 = { 69 1c [2] 1d 04 [2] 5a 06 [2] 1d 17 [2] 53 1b [2] 5f 11 [2] 48 1a [2] 53 54 [2] 6e }

  condition:
    any of them
}
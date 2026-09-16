rule TTP_XOR_MULT_DOSStub_3d69 {
  strings:
    $key_3d69 = { 69 01 [2] 1d 19 [2] 5a 1b [2] 1d 0a [2] 53 06 [2] 5f 0c [2] 48 07 [2] 53 49 [2] 6e }

  condition:
    any of them
}
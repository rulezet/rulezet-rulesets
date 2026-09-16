rule TTP_XOR_MULT_DOSStub_3d09 {
  strings:
    $key_3d09 = { 69 61 [2] 1d 79 [2] 5a 7b [2] 1d 6a [2] 53 66 [2] 5f 6c [2] 48 67 [2] 53 29 [2] 6e }

  condition:
    any of them
}
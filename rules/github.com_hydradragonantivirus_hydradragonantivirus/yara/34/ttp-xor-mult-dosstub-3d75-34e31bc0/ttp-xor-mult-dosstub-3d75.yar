rule TTP_XOR_MULT_DOSStub_3d75 {
  strings:
    $key_3d75 = { 69 1d [2] 1d 05 [2] 5a 07 [2] 1d 16 [2] 53 1a [2] 5f 10 [2] 48 1b [2] 53 55 [2] 6e }

  condition:
    any of them
}
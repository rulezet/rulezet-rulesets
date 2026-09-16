rule TTP_XOR_MULT_DOSStub_6905 {
  strings:
    $key_6905 = { 3d 6d [2] 49 75 [2] 0e 77 [2] 49 66 [2] 07 6a [2] 0b 60 [2] 1c 6b [2] 07 25 [2] 3a }

  condition:
    any of them
}
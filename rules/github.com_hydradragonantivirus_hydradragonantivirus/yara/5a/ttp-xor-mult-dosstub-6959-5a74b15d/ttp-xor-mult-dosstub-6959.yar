rule TTP_XOR_MULT_DOSStub_6959 {
  strings:
    $key_6959 = { 3d 31 [2] 49 29 [2] 0e 2b [2] 49 3a [2] 07 36 [2] 0b 3c [2] 1c 37 [2] 07 79 [2] 3a }

  condition:
    any of them
}
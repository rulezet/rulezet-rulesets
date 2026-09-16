rule TTP_XOR_MULT_DOSStub_4952 {
  strings:
    $key_4952 = { 1d 3a [2] 69 22 [2] 2e 20 [2] 69 31 [2] 27 3d [2] 2b 37 [2] 3c 3c [2] 27 72 [2] 1a }

  condition:
    any of them
}
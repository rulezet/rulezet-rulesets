rule TTP_XOR_MULT_DOSStub_6948 {
  strings:
    $key_6948 = { 3d 20 [2] 49 38 [2] 0e 3a [2] 49 2b [2] 07 27 [2] 0b 2d [2] 1c 26 [2] 07 68 [2] 3a }

  condition:
    any of them
}
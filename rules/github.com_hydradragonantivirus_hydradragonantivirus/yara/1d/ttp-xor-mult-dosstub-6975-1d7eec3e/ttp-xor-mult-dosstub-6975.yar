rule TTP_XOR_MULT_DOSStub_6975 {
  strings:
    $key_6975 = { 3d 1d [2] 49 05 [2] 0e 07 [2] 49 16 [2] 07 1a [2] 0b 10 [2] 1c 1b [2] 07 55 [2] 3a }

  condition:
    any of them
}
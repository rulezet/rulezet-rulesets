rule TTP_XOR_MULT_DOSStub_6973 {
  strings:
    $key_6973 = { 3d 1b [2] 49 03 [2] 0e 01 [2] 49 10 [2] 07 1c [2] 0b 16 [2] 1c 1d [2] 07 53 [2] 3a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6928 {
  strings:
    $key_6928 = { 3d 40 [2] 49 58 [2] 0e 5a [2] 49 4b [2] 07 47 [2] 0b 4d [2] 1c 46 [2] 07 08 [2] 3a }

  condition:
    any of them
}
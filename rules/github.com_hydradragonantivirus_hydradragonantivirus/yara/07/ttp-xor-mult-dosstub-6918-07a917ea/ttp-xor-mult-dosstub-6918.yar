rule TTP_XOR_MULT_DOSStub_6918 {
  strings:
    $key_6918 = { 3d 70 [2] 49 68 [2] 0e 6a [2] 49 7b [2] 07 77 [2] 0b 7d [2] 1c 76 [2] 07 38 [2] 3a }

  condition:
    any of them
}
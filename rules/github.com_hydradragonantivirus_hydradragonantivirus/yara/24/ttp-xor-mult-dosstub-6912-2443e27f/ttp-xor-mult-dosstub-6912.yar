rule TTP_XOR_MULT_DOSStub_6912 {
  strings:
    $key_6912 = { 3d 7a [2] 49 62 [2] 0e 60 [2] 49 71 [2] 07 7d [2] 0b 77 [2] 1c 7c [2] 07 32 [2] 3a }

  condition:
    any of them
}
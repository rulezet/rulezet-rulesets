rule TTP_XOR_MULT_DOSStub_6902 {
  strings:
    $key_6902 = { 3d 6a [2] 49 72 [2] 0e 70 [2] 49 61 [2] 07 6d [2] 0b 67 [2] 1c 6c [2] 07 22 [2] 3a }

  condition:
    any of them
}
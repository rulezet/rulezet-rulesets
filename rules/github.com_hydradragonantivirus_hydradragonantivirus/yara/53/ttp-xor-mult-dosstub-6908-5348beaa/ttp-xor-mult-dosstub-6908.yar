rule TTP_XOR_MULT_DOSStub_6908 {
  strings:
    $key_6908 = { 3d 60 [2] 49 78 [2] 0e 7a [2] 49 6b [2] 07 67 [2] 0b 6d [2] 1c 66 [2] 07 28 [2] 3a }

  condition:
    any of them
}
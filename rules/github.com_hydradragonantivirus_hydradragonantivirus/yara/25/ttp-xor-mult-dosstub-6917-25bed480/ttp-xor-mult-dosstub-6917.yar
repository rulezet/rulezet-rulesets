rule TTP_XOR_MULT_DOSStub_6917 {
  strings:
    $key_6917 = { 3d 7f [2] 49 67 [2] 0e 65 [2] 49 74 [2] 07 78 [2] 0b 72 [2] 1c 79 [2] 07 37 [2] 3a }

  condition:
    any of them
}
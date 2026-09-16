rule TTP_XOR_MULT_DOSStub_6927 {
  strings:
    $key_6927 = { 3d 4f [2] 49 57 [2] 0e 55 [2] 49 44 [2] 07 48 [2] 0b 42 [2] 1c 49 [2] 07 07 [2] 3a }

  condition:
    any of them
}
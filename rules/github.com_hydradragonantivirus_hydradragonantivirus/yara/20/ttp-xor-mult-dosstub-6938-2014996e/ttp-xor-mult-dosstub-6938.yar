rule TTP_XOR_MULT_DOSStub_6938 {
  strings:
    $key_6938 = { 3d 50 [2] 49 48 [2] 0e 4a [2] 49 5b [2] 07 57 [2] 0b 5d [2] 1c 56 [2] 07 18 [2] 3a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6940 {
  strings:
    $key_6940 = { 3d 28 [2] 49 30 [2] 0e 32 [2] 49 23 [2] 07 2f [2] 0b 25 [2] 1c 2e [2] 07 60 [2] 3a }

  condition:
    any of them
}
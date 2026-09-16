rule TTP_XOR_MULT_DOSStub_6957 {
  strings:
    $key_6957 = { 3d 3f [2] 49 27 [2] 0e 25 [2] 49 34 [2] 07 38 [2] 0b 32 [2] 1c 39 [2] 07 77 [2] 3a }

  condition:
    any of them
}
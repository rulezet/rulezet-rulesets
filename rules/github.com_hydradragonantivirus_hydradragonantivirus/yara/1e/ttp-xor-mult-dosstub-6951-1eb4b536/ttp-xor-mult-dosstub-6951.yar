rule TTP_XOR_MULT_DOSStub_6951 {
  strings:
    $key_6951 = { 3d 39 [2] 49 21 [2] 0e 23 [2] 49 32 [2] 07 3e [2] 0b 34 [2] 1c 3f [2] 07 71 [2] 3a }

  condition:
    any of them
}
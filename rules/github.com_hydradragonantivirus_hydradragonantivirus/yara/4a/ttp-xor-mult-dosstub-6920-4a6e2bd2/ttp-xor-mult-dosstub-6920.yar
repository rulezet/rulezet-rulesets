rule TTP_XOR_MULT_DOSStub_6920 {
  strings:
    $key_6920 = { 3d 48 [2] 49 50 [2] 0e 52 [2] 49 43 [2] 07 4f [2] 0b 45 [2] 1c 4e [2] 07 00 [2] 3a }

  condition:
    any of them
}
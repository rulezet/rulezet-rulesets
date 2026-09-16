rule TTP_XOR_MULT_DOSStub_6970 {
  strings:
    $key_6970 = { 3d 18 [2] 49 00 [2] 0e 02 [2] 49 13 [2] 07 1f [2] 0b 15 [2] 1c 1e [2] 07 50 [2] 3a }

  condition:
    any of them
}
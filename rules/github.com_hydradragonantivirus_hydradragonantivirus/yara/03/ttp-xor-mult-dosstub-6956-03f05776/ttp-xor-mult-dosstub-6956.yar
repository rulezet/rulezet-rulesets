rule TTP_XOR_MULT_DOSStub_6956 {
  strings:
    $key_6956 = { 3d 3e [2] 49 26 [2] 0e 24 [2] 49 35 [2] 07 39 [2] 0b 33 [2] 1c 38 [2] 07 76 [2] 3a }

  condition:
    any of them
}
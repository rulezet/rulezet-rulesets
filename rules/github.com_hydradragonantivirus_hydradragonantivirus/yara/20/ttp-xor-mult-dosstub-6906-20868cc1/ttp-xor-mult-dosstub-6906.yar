rule TTP_XOR_MULT_DOSStub_6906 {
  strings:
    $key_6906 = { 3d 6e [2] 49 76 [2] 0e 74 [2] 49 65 [2] 07 69 [2] 0b 63 [2] 1c 68 [2] 07 26 [2] 3a }

  condition:
    any of them
}
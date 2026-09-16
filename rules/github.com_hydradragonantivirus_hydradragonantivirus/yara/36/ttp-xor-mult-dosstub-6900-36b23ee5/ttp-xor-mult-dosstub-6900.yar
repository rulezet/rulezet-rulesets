rule TTP_XOR_MULT_DOSStub_6900 {
  strings:
    $key_6900 = { 3d 68 [2] 49 70 [2] 0e 72 [2] 49 63 [2] 07 6f [2] 0b 65 [2] 1c 6e [2] 07 20 [2] 3a }

  condition:
    any of them
}
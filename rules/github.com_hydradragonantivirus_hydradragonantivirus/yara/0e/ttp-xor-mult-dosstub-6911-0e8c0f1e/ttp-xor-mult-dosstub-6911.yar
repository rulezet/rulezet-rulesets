rule TTP_XOR_MULT_DOSStub_6911 {
  strings:
    $key_6911 = { 3d 79 [2] 49 61 [2] 0e 63 [2] 49 72 [2] 07 7e [2] 0b 74 [2] 1c 7f [2] 07 31 [2] 3a }

  condition:
    any of them
}
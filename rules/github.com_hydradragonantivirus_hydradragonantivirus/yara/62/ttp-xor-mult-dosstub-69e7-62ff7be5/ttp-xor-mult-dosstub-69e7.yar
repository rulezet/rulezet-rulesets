rule TTP_XOR_MULT_DOSStub_69e7 {
  strings:
    $key_69e7 = { 3d 8f [2] 49 97 [2] 0e 95 [2] 49 84 [2] 07 88 [2] 0b 82 [2] 1c 89 [2] 07 c7 [2] 3a }

  condition:
    any of them
}
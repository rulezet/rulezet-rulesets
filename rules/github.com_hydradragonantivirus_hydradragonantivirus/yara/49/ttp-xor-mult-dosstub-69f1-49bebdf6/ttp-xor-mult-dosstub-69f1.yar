rule TTP_XOR_MULT_DOSStub_69f1 {
  strings:
    $key_69f1 = { 3d 99 [2] 49 81 [2] 0e 83 [2] 49 92 [2] 07 9e [2] 0b 94 [2] 1c 9f [2] 07 d1 [2] 3a }

  condition:
    any of them
}
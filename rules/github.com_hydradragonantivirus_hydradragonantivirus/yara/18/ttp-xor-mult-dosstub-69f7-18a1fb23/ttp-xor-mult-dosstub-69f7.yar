rule TTP_XOR_MULT_DOSStub_69f7 {
  strings:
    $key_69f7 = { 3d 9f [2] 49 87 [2] 0e 85 [2] 49 94 [2] 07 98 [2] 0b 92 [2] 1c 99 [2] 07 d7 [2] 3a }

  condition:
    any of them
}
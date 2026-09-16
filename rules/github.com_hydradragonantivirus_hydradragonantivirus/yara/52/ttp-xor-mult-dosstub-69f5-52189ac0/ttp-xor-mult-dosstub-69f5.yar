rule TTP_XOR_MULT_DOSStub_69f5 {
  strings:
    $key_69f5 = { 3d 9d [2] 49 85 [2] 0e 87 [2] 49 96 [2] 07 9a [2] 0b 90 [2] 1c 9b [2] 07 d5 [2] 3a }

  condition:
    any of them
}
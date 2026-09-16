rule TTP_XOR_MULT_DOSStub_69f8 {
  strings:
    $key_69f8 = { 3d 90 [2] 49 88 [2] 0e 8a [2] 49 9b [2] 07 97 [2] 0b 9d [2] 1c 96 [2] 07 d8 [2] 3a }

  condition:
    any of them
}
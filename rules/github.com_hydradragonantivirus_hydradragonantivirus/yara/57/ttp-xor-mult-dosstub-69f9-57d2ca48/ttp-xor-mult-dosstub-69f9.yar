rule TTP_XOR_MULT_DOSStub_69f9 {
  strings:
    $key_69f9 = { 3d 91 [2] 49 89 [2] 0e 8b [2] 49 9a [2] 07 96 [2] 0b 9c [2] 1c 97 [2] 07 d9 [2] 3a }

  condition:
    any of them
}
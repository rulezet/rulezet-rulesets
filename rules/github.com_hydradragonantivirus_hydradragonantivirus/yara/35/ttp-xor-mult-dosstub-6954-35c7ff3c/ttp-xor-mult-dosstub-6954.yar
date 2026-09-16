rule TTP_XOR_MULT_DOSStub_6954 {
  strings:
    $key_6954 = { 3d 3c [2] 49 24 [2] 0e 26 [2] 49 37 [2] 07 3b [2] 0b 31 [2] 1c 3a [2] 07 74 [2] 3a }

  condition:
    any of them
}
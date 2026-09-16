rule TTP_XOR_MULT_DOSStub_6909 {
  strings:
    $key_6909 = { 3d 61 [2] 49 79 [2] 0e 7b [2] 49 6a [2] 07 66 [2] 0b 6c [2] 1c 67 [2] 07 29 [2] 3a }

  condition:
    any of them
}
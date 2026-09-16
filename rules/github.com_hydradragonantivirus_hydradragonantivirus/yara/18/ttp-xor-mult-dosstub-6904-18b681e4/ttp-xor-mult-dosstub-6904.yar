rule TTP_XOR_MULT_DOSStub_6904 {
  strings:
    $key_6904 = { 3d 6c [2] 49 74 [2] 0e 76 [2] 49 67 [2] 07 6b [2] 0b 61 [2] 1c 6a [2] 07 24 [2] 3a }

  condition:
    any of them
}
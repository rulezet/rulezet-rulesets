rule TTP_XOR_MULT_DOSStub_6963 {
  strings:
    $key_6963 = { 3d 0b [2] 49 13 [2] 0e 11 [2] 49 00 [2] 07 0c [2] 0b 06 [2] 1c 0d [2] 07 43 [2] 3a }

  condition:
    any of them
}
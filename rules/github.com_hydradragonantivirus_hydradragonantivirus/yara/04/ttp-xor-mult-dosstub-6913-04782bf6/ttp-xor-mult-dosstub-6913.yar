rule TTP_XOR_MULT_DOSStub_6913 {
  strings:
    $key_6913 = { 3d 7b [2] 49 63 [2] 0e 61 [2] 49 70 [2] 07 7c [2] 0b 76 [2] 1c 7d [2] 07 33 [2] 3a }

  condition:
    any of them
}
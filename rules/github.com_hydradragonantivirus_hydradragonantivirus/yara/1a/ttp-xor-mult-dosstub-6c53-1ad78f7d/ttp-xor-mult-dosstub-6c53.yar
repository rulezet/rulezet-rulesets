rule TTP_XOR_MULT_DOSStub_6c53 {
  strings:
    $key_6c53 = { 38 3b [2] 4c 23 [2] 0b 21 [2] 4c 30 [2] 02 3c [2] 0e 36 [2] 19 3d [2] 02 73 [2] 3f }

  condition:
    any of them
}
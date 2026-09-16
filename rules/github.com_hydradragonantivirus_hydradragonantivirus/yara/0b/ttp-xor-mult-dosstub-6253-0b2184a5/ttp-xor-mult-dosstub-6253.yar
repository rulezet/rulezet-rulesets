rule TTP_XOR_MULT_DOSStub_6253 {
  strings:
    $key_6253 = { 36 3b [2] 42 23 [2] 05 21 [2] 42 30 [2] 0c 3c [2] 00 36 [2] 17 3d [2] 0c 73 [2] 31 }

  condition:
    any of them
}
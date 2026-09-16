rule TTP_XOR_MULT_DOSStub_4653 {
  strings:
    $key_4653 = { 12 3b [2] 66 23 [2] 21 21 [2] 66 30 [2] 28 3c [2] 24 36 [2] 33 3d [2] 28 73 [2] 15 }

  condition:
    any of them
}
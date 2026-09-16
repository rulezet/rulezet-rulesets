rule TTP_XOR_MULT_DOSStub_2153 {
  strings:
    $key_2153 = { 75 3b [2] 01 23 [2] 46 21 [2] 01 30 [2] 4f 3c [2] 43 36 [2] 54 3d [2] 4f 73 [2] 72 }

  condition:
    any of them
}
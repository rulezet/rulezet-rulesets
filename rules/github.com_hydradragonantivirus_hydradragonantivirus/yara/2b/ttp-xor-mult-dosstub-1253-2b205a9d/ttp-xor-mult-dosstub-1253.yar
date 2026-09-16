rule TTP_XOR_MULT_DOSStub_1253 {
  strings:
    $key_1253 = { 46 3b [2] 32 23 [2] 75 21 [2] 32 30 [2] 7c 3c [2] 70 36 [2] 67 3d [2] 7c 73 [2] 41 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1653 {
  strings:
    $key_1653 = { 42 3b [2] 36 23 [2] 71 21 [2] 36 30 [2] 78 3c [2] 74 36 [2] 63 3d [2] 78 73 [2] 45 }

  condition:
    any of them
}
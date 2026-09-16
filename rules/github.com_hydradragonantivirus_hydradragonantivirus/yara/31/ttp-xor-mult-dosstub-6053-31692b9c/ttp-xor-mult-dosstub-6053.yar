rule TTP_XOR_MULT_DOSStub_6053 {
  strings:
    $key_6053 = { 34 3b [2] 40 23 [2] 07 21 [2] 40 30 [2] 0e 3c [2] 02 36 [2] 15 3d [2] 0e 73 [2] 33 }

  condition:
    any of them
}
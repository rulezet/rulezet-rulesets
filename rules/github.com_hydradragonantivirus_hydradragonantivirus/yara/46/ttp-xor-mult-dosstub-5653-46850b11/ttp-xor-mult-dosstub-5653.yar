rule TTP_XOR_MULT_DOSStub_5653 {
  strings:
    $key_5653 = { 02 3b [2] 76 23 [2] 31 21 [2] 76 30 [2] 38 3c [2] 34 36 [2] 23 3d [2] 38 73 [2] 05 }

  condition:
    any of them
}
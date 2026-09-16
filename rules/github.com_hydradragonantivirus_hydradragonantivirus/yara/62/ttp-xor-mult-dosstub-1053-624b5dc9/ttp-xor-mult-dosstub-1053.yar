rule TTP_XOR_MULT_DOSStub_1053 {
  strings:
    $key_1053 = { 44 3b [2] 30 23 [2] 77 21 [2] 30 30 [2] 7e 3c [2] 72 36 [2] 65 3d [2] 7e 73 [2] 43 }

  condition:
    any of them
}
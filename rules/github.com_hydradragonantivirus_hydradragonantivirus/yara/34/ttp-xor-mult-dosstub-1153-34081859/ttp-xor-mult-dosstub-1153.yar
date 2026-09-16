rule TTP_XOR_MULT_DOSStub_1153 {
  strings:
    $key_1153 = { 45 3b [2] 31 23 [2] 76 21 [2] 31 30 [2] 7f 3c [2] 73 36 [2] 64 3d [2] 7f 73 [2] 42 }

  condition:
    any of them
}
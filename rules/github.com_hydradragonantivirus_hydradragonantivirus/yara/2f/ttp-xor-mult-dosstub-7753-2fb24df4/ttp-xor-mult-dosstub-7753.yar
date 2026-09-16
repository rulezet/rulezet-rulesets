rule TTP_XOR_MULT_DOSStub_7753 {
  strings:
    $key_7753 = { 23 3b [2] 57 23 [2] 10 21 [2] 57 30 [2] 19 3c [2] 15 36 [2] 02 3d [2] 19 73 [2] 24 }

  condition:
    any of them
}
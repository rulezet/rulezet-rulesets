rule TTP_XOR_MULT_DOSStub_2753 {
  strings:
    $key_2753 = { 73 3b [2] 07 23 [2] 40 21 [2] 07 30 [2] 49 3c [2] 45 36 [2] 52 3d [2] 49 73 [2] 74 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_6753 {
  strings:
    $key_6753 = { 33 3b [2] 47 23 [2] 00 21 [2] 47 30 [2] 09 3c [2] 05 36 [2] 12 3d [2] 09 73 [2] 34 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5a53 {
  strings:
    $key_5a53 = { 0e 3b [2] 7a 23 [2] 3d 21 [2] 7a 30 [2] 34 3c [2] 38 36 [2] 2f 3d [2] 34 73 [2] 09 }

  condition:
    any of them
}
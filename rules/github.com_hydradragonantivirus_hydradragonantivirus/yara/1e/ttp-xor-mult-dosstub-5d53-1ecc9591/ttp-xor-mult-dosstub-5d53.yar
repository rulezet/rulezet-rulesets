rule TTP_XOR_MULT_DOSStub_5d53 {
  strings:
    $key_5d53 = { 09 3b [2] 7d 23 [2] 3a 21 [2] 7d 30 [2] 33 3c [2] 3f 36 [2] 28 3d [2] 33 73 [2] 0e }

  condition:
    any of them
}
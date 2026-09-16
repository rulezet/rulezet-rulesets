rule TTP_XOR_MULT_DOSStub_3a03 {
  strings:
    $key_3a03 = { 6e 6b [2] 1a 73 [2] 5d 71 [2] 1a 60 [2] 54 6c [2] 58 66 [2] 4f 6d [2] 54 23 [2] 69 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1a03 {
  strings:
    $key_1a03 = { 4e 6b [2] 3a 73 [2] 7d 71 [2] 3a 60 [2] 74 6c [2] 78 66 [2] 6f 6d [2] 74 23 [2] 49 }

  condition:
    any of them
}
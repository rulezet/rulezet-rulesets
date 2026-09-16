rule TTP_XOR_MULT_DOSStub_1703 {
  strings:
    $key_1703 = { 43 6b [2] 37 73 [2] 70 71 [2] 37 60 [2] 79 6c [2] 75 66 [2] 62 6d [2] 79 23 [2] 44 }

  condition:
    any of them
}
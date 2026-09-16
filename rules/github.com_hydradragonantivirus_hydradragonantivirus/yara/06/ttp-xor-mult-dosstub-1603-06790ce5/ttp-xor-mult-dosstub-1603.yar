rule TTP_XOR_MULT_DOSStub_1603 {
  strings:
    $key_1603 = { 42 6b [2] 36 73 [2] 71 71 [2] 36 60 [2] 78 6c [2] 74 66 [2] 63 6d [2] 78 23 [2] 45 }

  condition:
    any of them
}
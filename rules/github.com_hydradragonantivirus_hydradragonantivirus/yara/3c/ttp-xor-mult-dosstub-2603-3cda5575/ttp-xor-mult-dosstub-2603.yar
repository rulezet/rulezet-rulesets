rule TTP_XOR_MULT_DOSStub_2603 {
  strings:
    $key_2603 = { 72 6b [2] 06 73 [2] 41 71 [2] 06 60 [2] 48 6c [2] 44 66 [2] 53 6d [2] 48 23 [2] 75 }

  condition:
    any of them
}
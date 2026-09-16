rule TTP_XOR_MULT_DOSStub_2103 {
  strings:
    $key_2103 = { 75 6b [2] 01 73 [2] 46 71 [2] 01 60 [2] 4f 6c [2] 43 66 [2] 54 6d [2] 4f 23 [2] 72 }

  condition:
    any of them
}
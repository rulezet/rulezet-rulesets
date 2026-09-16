rule TTP_XOR_MULT_DOSStub_5203 {
  strings:
    $key_5203 = { 06 6b [2] 72 73 [2] 35 71 [2] 72 60 [2] 3c 6c [2] 30 66 [2] 27 6d [2] 3c 23 [2] 01 }

  condition:
    any of them
}
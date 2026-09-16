rule TTP_XOR_MULT_DOSStub_6203 {
  strings:
    $key_6203 = { 36 6b [2] 42 73 [2] 05 71 [2] 42 60 [2] 0c 6c [2] 00 66 [2] 17 6d [2] 0c 23 [2] 31 }

  condition:
    any of them
}
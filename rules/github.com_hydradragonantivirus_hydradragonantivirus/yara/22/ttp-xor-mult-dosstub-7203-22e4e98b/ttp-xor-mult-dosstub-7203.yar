rule TTP_XOR_MULT_DOSStub_7203 {
  strings:
    $key_7203 = { 26 6b [2] 52 73 [2] 15 71 [2] 52 60 [2] 1c 6c [2] 10 66 [2] 07 6d [2] 1c 23 [2] 21 }

  condition:
    any of them
}
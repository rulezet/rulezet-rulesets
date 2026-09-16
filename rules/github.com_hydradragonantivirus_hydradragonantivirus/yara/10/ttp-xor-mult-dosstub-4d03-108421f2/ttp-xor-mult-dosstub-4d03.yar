rule TTP_XOR_MULT_DOSStub_4d03 {
  strings:
    $key_4d03 = { 19 6b [2] 6d 73 [2] 2a 71 [2] 6d 60 [2] 23 6c [2] 2f 66 [2] 38 6d [2] 23 23 [2] 1e }

  condition:
    any of them
}
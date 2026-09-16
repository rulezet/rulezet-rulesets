rule TTP_XOR_MULT_DOSStub_3403 {
  strings:
    $key_3403 = { 60 6b [2] 14 73 [2] 53 71 [2] 14 60 [2] 5a 6c [2] 56 66 [2] 41 6d [2] 5a 23 [2] 67 }

  condition:
    any of them
}
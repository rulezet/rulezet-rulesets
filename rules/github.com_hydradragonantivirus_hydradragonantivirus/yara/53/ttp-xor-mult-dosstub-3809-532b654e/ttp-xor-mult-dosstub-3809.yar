rule TTP_XOR_MULT_DOSStub_3809 {
  strings:
    $key_3809 = { 6c 61 [2] 18 79 [2] 5f 7b [2] 18 6a [2] 56 66 [2] 5a 6c [2] 4d 67 [2] 56 29 [2] 6b }

  condition:
    any of them
}
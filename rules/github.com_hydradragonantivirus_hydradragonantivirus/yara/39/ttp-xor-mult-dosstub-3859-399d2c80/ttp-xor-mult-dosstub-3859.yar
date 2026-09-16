rule TTP_XOR_MULT_DOSStub_3859 {
  strings:
    $key_3859 = { 6c 31 [2] 18 29 [2] 5f 2b [2] 18 3a [2] 56 36 [2] 5a 3c [2] 4d 37 [2] 56 79 [2] 6b }

  condition:
    any of them
}
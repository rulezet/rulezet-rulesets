rule TTP_XOR_MULT_DOSStub_0809 {
  strings:
    $key_0809 = { 5c 61 [2] 28 79 [2] 6f 7b [2] 28 6a [2] 66 66 [2] 6a 6c [2] 7d 67 [2] 66 29 [2] 5b }

  condition:
    any of them
}
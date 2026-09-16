rule TTP_XOR_MULT_DOSStub_6809 {
  strings:
    $key_6809 = { 3c 61 [2] 48 79 [2] 0f 7b [2] 48 6a [2] 06 66 [2] 0a 6c [2] 1d 67 [2] 06 29 [2] 3b }

  condition:
    any of them
}
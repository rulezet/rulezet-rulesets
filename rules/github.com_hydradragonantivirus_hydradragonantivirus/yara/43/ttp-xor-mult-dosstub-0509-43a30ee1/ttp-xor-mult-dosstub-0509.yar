rule TTP_XOR_MULT_DOSStub_0509 {
  strings:
    $key_0509 = { 51 61 [2] 25 79 [2] 62 7b [2] 25 6a [2] 6b 66 [2] 67 6c [2] 70 67 [2] 6b 29 [2] 56 }

  condition:
    any of them
}
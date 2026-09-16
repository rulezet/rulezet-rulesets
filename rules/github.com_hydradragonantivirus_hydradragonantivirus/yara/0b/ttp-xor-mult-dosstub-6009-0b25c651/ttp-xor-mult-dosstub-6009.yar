rule TTP_XOR_MULT_DOSStub_6009 {
  strings:
    $key_6009 = { 34 61 [2] 40 79 [2] 07 7b [2] 40 6a [2] 0e 66 [2] 02 6c [2] 15 67 [2] 0e 29 [2] 33 }

  condition:
    any of them
}
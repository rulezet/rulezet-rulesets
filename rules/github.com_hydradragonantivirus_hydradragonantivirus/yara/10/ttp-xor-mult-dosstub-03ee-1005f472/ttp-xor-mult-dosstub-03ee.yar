rule TTP_XOR_MULT_DOSStub_03ee {
  strings:
    $key_03ee = { 57 86 [2] 23 9e [2] 64 9c [2] 23 8d [2] 6d 81 [2] 61 8b [2] 76 80 [2] 6d ce [2] 50 }

  condition:
    any of them
}
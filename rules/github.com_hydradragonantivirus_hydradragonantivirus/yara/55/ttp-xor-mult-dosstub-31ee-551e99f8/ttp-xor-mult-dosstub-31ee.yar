rule TTP_XOR_MULT_DOSStub_31ee {
  strings:
    $key_31ee = { 65 86 [2] 11 9e [2] 56 9c [2] 11 8d [2] 5f 81 [2] 53 8b [2] 44 80 [2] 5f ce [2] 62 }

  condition:
    any of them
}
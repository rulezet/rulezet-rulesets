rule TTP_XOR_MULT_DOSStub_17ee {
  strings:
    $key_17ee = { 43 86 [2] 37 9e [2] 70 9c [2] 37 8d [2] 79 81 [2] 75 8b [2] 62 80 [2] 79 ce [2] 44 }

  condition:
    any of them
}
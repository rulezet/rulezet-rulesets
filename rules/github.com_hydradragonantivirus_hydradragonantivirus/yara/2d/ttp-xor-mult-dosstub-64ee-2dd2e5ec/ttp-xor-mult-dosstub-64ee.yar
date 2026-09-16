rule TTP_XOR_MULT_DOSStub_64ee {
  strings:
    $key_64ee = { 30 86 [2] 44 9e [2] 03 9c [2] 44 8d [2] 0a 81 [2] 06 8b [2] 11 80 [2] 0a ce [2] 37 }

  condition:
    any of them
}
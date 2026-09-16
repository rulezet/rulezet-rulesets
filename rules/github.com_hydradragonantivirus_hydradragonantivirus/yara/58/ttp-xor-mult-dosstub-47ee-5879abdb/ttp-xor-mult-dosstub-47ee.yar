rule TTP_XOR_MULT_DOSStub_47ee {
  strings:
    $key_47ee = { 13 86 [2] 67 9e [2] 20 9c [2] 67 8d [2] 29 81 [2] 25 8b [2] 32 80 [2] 29 ce [2] 14 }

  condition:
    any of them
}
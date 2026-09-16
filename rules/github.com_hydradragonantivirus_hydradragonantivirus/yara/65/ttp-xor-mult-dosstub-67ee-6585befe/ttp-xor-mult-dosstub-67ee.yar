rule TTP_XOR_MULT_DOSStub_67ee {
  strings:
    $key_67ee = { 33 86 [2] 47 9e [2] 00 9c [2] 47 8d [2] 09 81 [2] 05 8b [2] 12 80 [2] 09 ce [2] 34 }

  condition:
    any of them
}
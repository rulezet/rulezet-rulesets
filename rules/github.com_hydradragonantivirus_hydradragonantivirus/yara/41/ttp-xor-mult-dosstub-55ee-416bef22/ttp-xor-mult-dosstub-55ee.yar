rule TTP_XOR_MULT_DOSStub_55ee {
  strings:
    $key_55ee = { 01 86 [2] 75 9e [2] 32 9c [2] 75 8d [2] 3b 81 [2] 37 8b [2] 20 80 [2] 3b ce [2] 06 }

  condition:
    any of them
}